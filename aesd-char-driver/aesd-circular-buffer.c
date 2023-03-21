/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    // Error checking for pointers
    if(buffer == NULL || entry_offset_byte_rtn == NULL)
    {
        return NULL;
    }

    int size_until_pos = 0;
    uint8_t entry_index = buffer -> out_offs;
    bool entry_not_found = false;

    // While size is less than charactr offset, scan the buffer
    while((size_until_pos + buffer -> entry[entry_index].size - 1) < char_offset)
    {
        size_until_pos += (buffer -> entry[entry_index].size);
        entry_index = (entry_index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

        // If all the entries have been scanned, required char_offset is beyond the buffer
        if(entry_index == buffer -> in_offs)
        {
            entry_not_found = true;
            break;
        }
    }

    if(entry_not_found)
    {
        return NULL;
    }

    *entry_offset_byte_rtn = char_offset - size_until_pos;
    
    return &(buffer -> entry[entry_index]); 
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
const char* aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    const char* return_ptr = NULL;

    // Error checking for pointers
    if(buffer == NULL || add_entry == NULL)
    {
        return NULL;
    }

    // If buff is full, return pointer to be freed
    if(buffer -> full)
    {
        return_ptr = buffer -> entry[buffer -> in_offs].buffptr;
    }

    // Add entry and update in_offs
    buffer -> entry[(buffer -> in_offs)] = *add_entry;
    buffer -> in_offs = ((buffer -> in_offs) + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    // If buffer is full, update out_offs
    if(buffer -> full)
    {
        buffer -> out_offs = ((buffer -> out_offs) + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    // If in = out, buffer is full
    if(buffer -> in_offs == buffer -> out_offs)
    {
        buffer -> full = true;
    }

    return return_ptr;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
