#include "mymalloc.h"
#include <sys/mman.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

typedef struct Block {
  // Size of the block (including meta-data size)
  // allocated bit is 1st bit (lsb)
  // fencepost bit is 2nd bit
  //
  size_t size;
  // A pointer to the previous unallocated block
  // In the case of the block being a fencepost, 
  // points to the prev chuncks fencepost
  struct Block *prev;
  // A pointer to the next unallocated block
  // In the case of the block being a fencepost, 
  // points to the next chuncks fencepost
  struct Block *next;
} Block;

//size of header
const size_t kHeaderSize = sizeof(Block);
//size of the footer
const size_t kFooterSize = sizeof(size_t);
// Size of meta-data of a (unallocated) Block
const size_t kMetadataSize = kHeaderSize + kFooterSize;
//size of the max allocation possible
const size_t kMaxAllocationSize = (16ull << 20);

//list of the entries
Block *entries[N_LISTS+1];
//the first fencepost
Block *start_fencepost = NULL;
//the final fencepost
Block *end_fencepost = NULL;

Block *oversized_entry = NULL;

///////////////////////////////////////////////////////////

/* Function: pad
 * -------------------------------
 *  pads a size_t up to be word aligned
 *  
 *  size: a potentially non-word aligned size_t
 *
 *  returns: the size_t word aligned
 */
inline static size_t pad(size_t size) {
  const size_t mask = sizeof(size_t) - 1;
  return (size + mask) & ~mask;
}


/* Function: get_size
 * -------------------------------
 *  getter for a blocks size without allocated bit
 *  
 *  block: the block to get the size of
 *
 *  returns: the size of the block 
 */
static size_t get_size(Block *block){
  return (size_t)((block->size)&-8);
}

/* Function: get_footer
 * -------------------------------
 *  gets the footer of a given block whose size is set
 *  
 *  block: a block in the free list whose size is set
 *
 *  returns: a pointer to the footer of the given block
 */
static size_t *get_footer(Block *block){
  return (size_t*) ((((char*)block) + get_size(block)) - kFooterSize);
}

/* Function: set_size
 * -------------------------------
 *  setter for a blocks size without changing the allocation bit
 *  also sets the fencepost to be false
 *  
 *  block: the block to set it's allocation status
 *  size: the new size of the block
 */
static void set_size(Block *block, size_t size){
  //set the size in the header and make fencepost 0
  block->size = ((block->size)&5) | (size&-8);
  //set the size in the footer
  size_t *footer = get_footer(block);
  *footer = (size_t) block->size;
}

/* Function: get_allocated
 * -------------------------------
 *  getter for a blocks allocation status
 *  
 *  block: the block to check it's allocation status
 *
 *  returns: whether a block is allocated or not
 */
static bool get_allocated(Block *block){
  return ((block->size)&1);
}

/* Function: set_allocated
 * -------------------------------
 *  setter for a blocks allocation status
 *  size must have already been set!
 *  
 *  block: the block to set it's allocation status
 *  a: the state to change the allocation to be
 */
static void set_allocated(Block *block, bool a){
  //set the allocated bit in the header
  block->size = ((((block->size)>>1)<<1) | (int) a);
  //set the allocated bit in the footer
  size_t *footer = get_footer(block);
  *footer = (size_t) block->size;
}

/* Function: get_fencepost
 * -------------------------------
 *  getter for a blocks fencepost status
 *  
 *  block: the block to check it's fencepost status
 *
 *  returns: whether a block is a fencepost or not
 */
static bool get_fencepost(Block *block){
  return (((block->size)&2)>>1);
}

/* Function: set_fencepost
 * -------------------------------
 *  sets a blocks fencepost status to true
 *  size must have already been set!
 *  
 *  block: the block to set it's fencepost status
 */
static void set_fencepost(Block *block){
  block->size = (block->size) | 2;
}

/* Function: get_right_block
 * -------------------------------
 *  gets the block to the right of the given block
 *  
 *  block: a block within the free list
 *
 *  returns: the block to the right of the given block
 */
static Block *get_right_block(Block *block) {
  //get the next block
  Block *right = (Block *) (((size_t)block) + get_size(block));

  //check to see if it's a fencepost
  if(get_fencepost(right)){
    //check to see if we are at the final fencepost in the list
    if(right->next == NULL){
      return right;
    }
    //otherwise get the next block in the chunck over
    right = get_right_block(right->next);
  }
  return right;
}

/* Function: get_left_block
 * -------------------------------
 *  gets the block to the left of the given block
 *  
 *  block: a block within the free list
 *
 *  returns: the block to the left of the given block
 */
static Block *get_left_block(Block *block) {
  //get the previous block
  Block *left = (Block *) (((char*)block) - ((*(size_t*)(((char*)block) - kFooterSize))&-8));

  //check to see if it's a fencepost
  if(get_fencepost(left)){
    //check to see if we are at the final fencepost in the list
    if(left->prev == NULL){
      return left;
    }
    //otherwise get the previous block in the chunck before
    left = get_left_block(left->prev);
  }
  return left;
}

/* Function: request_chunk
 * -------------------------------
 *  requests a chunck of 4MB of memory from the OS
 *  formating correctly with fence posts
 *
 *  returns: a pointer to the first block in the chunck
 */
static Block* request_chunk(){
  Block *start = mmap(NULL, ARENA_SIZE, (PROT_READ | PROT_WRITE), (MAP_PRIVATE | MAP_ANONYMOUS), 0, 0);
  //create the beginning fencepost
  set_size(start, kMetadataSize);
  set_allocated(start, true);
  set_fencepost(start);

  //create the block
  Block *rtn = get_right_block(start);
  set_size(rtn, (size_t)(ARENA_SIZE - (2*kMetadataSize)));
  set_allocated(rtn, false);

  //create the end fencepost
  Block *end = get_right_block(rtn);
  set_size(end, kMetadataSize);
  set_allocated(end, true);
  set_fencepost(end);

  //set up or maintain the end and start fenceposts
  if(start_fencepost == NULL && end_fencepost == NULL){
    start_fencepost = start;
    end_fencepost = end;
  }
  else{
    end_fencepost->next = start;
    start->prev = end_fencepost;
    end_fencepost = end;
  }


  rtn->prev = start_fencepost;
  rtn->next = end_fencepost;
  start->next = end;

  return rtn;
}

static void *block_to_data(Block *block){
  return (void*)(((size_t)block) + sizeof(size_t));
}

static Block *data_to_block(void *ptr){
  return (Block*)(((size_t)ptr) - sizeof(size_t));
}

/* Function: size_to_index
 * -------------------------------
 *  Converts a size of a block into the coresponding
 *  index in the free list list
 *
 *  size: the size of a block
 *
 *  returns: the coresponding index of a block size in the
 *  free list list
 */
static int size_to_index(size_t size){
  int rtn = (int)((size-kMetadataSize)/8);
  if(rtn >= N_LISTS+1){
    rtn = N_LISTS;
  } 
  return rtn;
}

static void insert_block(Block *block){
  int index = size_to_index(get_size(block));

  //iterate through the blocks relevent free list 
  //to find the block before it in the list 
  Block *e = entries[index];
  
  if(e == NULL){
    //then block is the first block in that list
    block->next = end_fencepost;
    block->prev = start_fencepost;
    entries[index] = block;
    return;
  }

  Block *prev_block = NULL;
  for(Block *b = e; !get_fencepost(b); b = b->next){
    if(((b->next)>block) && (b<block)){
      prev_block = b;
      break;
    }
  }
  

  if(prev_block == NULL){
    //this case occurs when all other blocks in the list
    //are allocated and hence entry is the final fencepost
    //or when the block is to become the first block in the
    //list
    block->next = (Block*) entries[index];
    if(!get_fencepost(entries[index])){
      block->prev = (Block*) entries[index]->prev;
      entries[index]->prev = (Block*) block;
    }
    else{
      block->prev = (Block*) start_fencepost;
    }
    entries[index] = block;
  }
  else{
    //fix the pointers
    if(!get_fencepost(prev_block->next)){
      prev_block->next->prev = (Block*) block;
    }
    block->next = (Block*) prev_block->next;
    prev_block->next = (Block*) block;
    block->prev = (Block*) prev_block;
  }
}

/* Function: split_block
 * -------------------------------
 *  splits a block into two blocks one of a given size and the other 
 *  of the remaining size
 *  
 *  block: an unallocated block within the free list
 *  size: the size of the new block wanting to be made
 *
 *  returns: the block of the given size
 */
static Block *split_block(Block *block, size_t size) {
  size_t total = get_size(block);

  //remove the block from the free list
  if(!get_fencepost(block->prev)){
    block->prev->next = block->prev;
  }
  else{
    //then the block is at the start of a list
    if(!get_fencepost(block->next)){
      entries[size_to_index(get_size(block))] = block->next;
      block->next->prev = block->prev;
    }
    else{
      //then the block was the only on in that list
      entries[size_to_index(get_size(block))] = NULL;
    }
      
  }
  if(!get_fencepost(block->next))
    block->next->prev = block->prev;

  //create the large block
  Block *left = block;
  set_size(left, (size_t)(total - size));
  set_allocated(left, false);

  //create the block of the given size
  Block *right = get_right_block(left);
  set_size(right, (size_t)(total - get_size(left)));
  set_allocated(right, false);

  insert_block(left);
  insert_block(right);

  return right;
}

/* Function: get_block
 * -------------------------------
 *  gets the block in a free list according to the malloc
 *  policy
 *  
 *  index: the index of the list
 *  size: the size of block needed
 *
 *  returns: an unallocated block in the given free list
 */
static Block *get_block(int index, size_t size){
  //iterate over the free blocks
  Block *block = NULL;
  for(Block *b = entries[index]; b!= NULL; b = b->next){
    if(!get_allocated(b) && get_size(b) >= size){
      block = b;
      break;
    }
  }

  return block;
}

//////////////////////////////////////////////////////////


void *my_malloc(size_t size)
{
  //index to the entry list
  int index;

  if(size <= 0 || size > kMaxAllocationSize){
    fprintf(stderr, "my_malloc: %s\n", strerror(EINVAL));
    return NULL;
  }

  size = pad(size + kMetadataSize-(2*sizeof(Block*)));
  if(size < kMetadataSize){
    size = kMetadataSize;
  }
  
  //find the index of the entry array for this block
  index = size_to_index(size);

  if(size > ARENA_SIZE - 2*kMetadataSize){
    //we need the next and prev pointers
    size += 2*sizeof(Block*);

    //calculate the size of the block we need
    size_t allocate_size = 2*ARENA_SIZE;
    while(allocate_size <= size)
      allocate_size+=ARENA_SIZE;

    //then request a block of that size
    Block *rtn = mmap(NULL, allocate_size, (PROT_READ | PROT_WRITE), (MAP_PRIVATE | MAP_ANONYMOUS), 0, 0);
    set_size(rtn, (size_t)(allocate_size));
    set_allocated(rtn, true);

    //then add the new oversized block to the oversized list
    if(oversized_entry == NULL){
      oversized_entry = rtn;
    }
    else{
      oversized_entry->prev = rtn;
      rtn->next = oversized_entry;
      oversized_entry = rtn;
    }
    
    //and return the data pointer
    return (void*)((((char*)rtn)+kHeaderSize));
  }

  if(entries[index] == NULL){
    if(entries[N_LISTS] == NULL){
      entries[N_LISTS] = request_chunk();
    }
    if(index != N_LISTS){
      //get a block from the big blocks
      Block *large = get_block(N_LISTS, 0);
      split_block(large, size);
    }
  }
  
  //get an unallocated block in the free list according to policy
  Block *block = get_block(index, size);

  //Check if block is still NULL
  if(block == NULL){
    Block *large = get_block(N_LISTS, 0);
    if(large == NULL){
      //request more memory
      entries[N_LISTS] = request_chunk();
      large = get_block(N_LISTS, 0);
    }
    split_block(large, size);
    //get an unallocated block in the free list according to policy
    block = get_block(index, size);
  }

  //check to break up
  if(get_size(block) >= size + (kMetadataSize<<1) + sizeof(size_t)){
    block = split_block(block, size);
  }

  //prepare the block and free list for return to user program
  set_allocated(block, true);

  //check to see if block is pointed to by entry
  if(get_allocated(entries[index])){
    if(!get_fencepost(block->next)){
      entries[index] = block->next;
    }
    else{
      entries[index] = NULL;
    }
  }

  //fix pointers in the free list
  //edge case when blocks prev/next is a fencepost
  if(!get_fencepost(block->prev)){
    block->prev->next = block->next;
  }
  if(!get_fencepost(block->next)){
    block->next->prev = block->prev;
  }

  return block_to_data(block);
}

void my_free(void *ptr)
{
  //first check to see if the pointer is within the oversized
  //list
  for(Block *b = oversized_entry; b != NULL; b = b->next){
    if((char*)ptr == (((char*)b)+kHeaderSize)){
      //remove the block from the oversized list
      if(b->prev != NULL)
        b->prev->next = b->next;
      if(b->next != NULL)
        b->next->prev = b->prev;

      if(oversized_entry == b){
        oversized_entry = b->next;
      }
      
      //unmap that memory
      int r = munmap(b, get_size(b));

      if(r != 0){
        fprintf(stderr, "my_free: %s\n", strerror(EINVAL));
        exit(EINVAL);
      }
      return;
    }
  }

  //then check if the pointer is within the other memory
  if(start_fencepost==NULL || start_fencepost->next == NULL){
    fprintf(stderr, "my_free: %s\n", strerror(EINVAL));
    exit(EINVAL);
  }

  //check to see if the pointer is between any of the fenceposts
  bool found = (ptr > start_fencepost && ptr < start_fencepost->next);
  for(Block* b = start_fencepost; b->next->next != NULL; b = b->next->next){
    if(ptr > b && ptr < b->next)
      found = true;
  }

  if(!found){
    fprintf(stderr, "my_free: %s\n", strerror(EINVAL));
    exit(EINVAL);
  }

  int index;
  if(ptr != NULL){
    Block *block = data_to_block(ptr);
    set_allocated(block, false);
    index = size_to_index(get_size(block));

    Block *left = get_left_block(block);
    Block *right = get_right_block(block);

    bool alloc_left = get_allocated(left);
    bool alloc_right = get_allocated(right);

    //check for when the left/right are in a different chunk
    if(left != (((char*)block) - (get_size(left))))
      alloc_left = false;

    if(right != (((char*)block) + (get_size(block))))
      alloc_right = true;

    if(alloc_left && alloc_right){
      //simply insert the block into it's list
      insert_block(block);
    }
    else if(alloc_right && !alloc_left){

      //fix the pointers to remove the left block from 
      //it's current list
      if(!get_fencepost(left->prev)){
        left->prev->next = left->next;
      }
      else{
        //then we know that left is pointed to by an entry
        //bc it is free and it's prev is a fencepost

        //move the entry along
        int left_index = size_to_index(get_size(left));
        if(!get_fencepost(left->next)){
          entries[left_index] = left->next;
          left->next->prev = left->prev;
        }
        else{
          entries[left_index] = NULL;
        }
      }

      if(!get_fencepost(left->next)){
        left->next->prev = left->prev;
      }
      else{
        //then left is at the end of a list must make
        //the new end point to the fencepost
        left->prev->next = left->next;
      }

      //add the block's size to the left block and set allocated bit
      set_size(left, get_size(left)+get_size(block));
      set_allocated(left, false);

      //then insert the new block into it's new list
      insert_block(left);
    }
    else if(alloc_left && !alloc_right){

      //fix the pointers to remove the right block from 
      //it's current list
      if(!get_fencepost(right->prev)){
        right->prev->next = right->next;
      }
      else{
        //then we know that right is pointed to by an entry
        //bc it is free and it's prev is a fencepost

        //move the entry along
        int right_index = size_to_index(get_size(right));
        if(!get_fencepost(right->next)){
          entries[right_index] = right->next;
          right->next->prev = right->prev;
        }
        else{
          entries[right_index] = NULL;
        }
      }

      if(!get_fencepost(right->next)){
        right->next->prev = right->prev;
      }
      else{
        //then right is at the end of a list must make
        //the new end point to the fencepost
        right->prev->next = right->next;
      }

      //add the right block's size to the block and set allocated bit
      set_size(block, get_size(block)+get_size(right));
      set_allocated(block, false);

      //then insert the new block into it's new list
      insert_block(block);
      
    }
    else if(!alloc_left && !alloc_right){
      //fix the pointers to remove the left block from 
      //it's current list
      if(!get_fencepost(left->prev)){
        left->prev->next = left->next;
      }
      else{
        //then we know that left is pointed to by an entry
        //bc it is free and it's prev is a fencepost

        //move the entry along
        int left_index = size_to_index(get_size(left));
        if(!get_fencepost(left->next)){
          entries[left_index] = left->next;
          left->next->prev = left->prev;
        }
        else{
          entries[left_index] = NULL;
        }
      }

      if(!get_fencepost(left->next)){
        left->next->prev = left->prev;
      }
      else{
        //then left is at the end of a list must make
        //the new end point to the fencepost
        left->prev->next = left->next;
      }

      //fix the pointers to remove the right block from 
      //it's current list
      if(!get_fencepost(right->prev)){
        right->prev->next = right->next;
      }
      else{
        //then we know that right is pointed to by an entry
        //bc it is free and it's prev is a fencepost

        //move the entry along
        int right_index = size_to_index(get_size(right));
        if(!get_fencepost(right->next)){
          entries[right_index] = right->next;
          right->next->prev = right->prev;
        }
        else{
          entries[right_index] = NULL;
        }
      }

      if(!get_fencepost(right->next)){
        right->next->prev = right->prev;
      }
      else{
        //then right is at the end of a list must make
        //the new end point to the fencepost
        right->prev->next = right->next;
      }

      //then add all the blocks size to the left block
      set_size(left, get_size(left)+get_size(block)+get_size(right));
      set_allocated(left, false);

      //then insert the new block into it's new list
      insert_block(left);

    }
  }
}
