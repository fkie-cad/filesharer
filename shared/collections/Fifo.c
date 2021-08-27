#if defined(__linux__) || defined(__linux) || defined(linux)
#include <errno.h>
#endif
#include <stdio.h>

#include "Fifo.h"




bool Fifo_init(PFifo fifo)
{
#ifdef DEBUG_PRINT
    printf("Fifo_init\n");
#endif
	fifo->front = NULL;
	fifo->head = NULL;
    fifo->size = 0;
    fifo->entry_header_size = 2 * sizeof(size_t);

    return true;
}

bool Fifo_clear(PFifo fifo)
{
#ifdef DEBUG_PRINT
    printf("Fifo_clear\n");
#endif
    PFifoEntry act = fifo->front;
    PFifoEntry tmp = NULL;
	
    while ( act != NULL )
    {
		tmp = act;
		act = act->next;
        free(tmp);
    }
	
    memset(fifo, 0, sizeof(*fifo));

    return true;
}

bool Fifo_destroy(PFifo fifo)
{
#ifdef DEBUG_PRINT
    printf("Fifo_destroy\n");
#endif
    
    Fifo_clear(fifo);
    free(fifo);

    return true;
}

size_t Fifo_push(PFifo fifo, const void* value, size_t value_size)
{
#ifdef DEBUG_PRINT
    printf("Fifo_push\n");
#endif
    errno = 0;
    PFifoEntry entry = (PFifoEntry)malloc(fifo->entry_header_size+value_size);
    int errsv = errno;
    if (!entry)
    {
        printf("ERROR (0x%x): malloc failed\n", errsv);
        return 0;
    }
    memset(entry, 0, fifo->entry_header_size + value_size);
    memcpy(&(entry->value)[0], value, value_size);
	
	entry->size = value_size;
	entry->next = NULL;
		
	if ( fifo->size == 0 )
	{
		fifo->front = entry;
        //fifo->front->last = NULL;
	}
	else
	{
		fifo->head->next = entry;
		//entry->last = fifo->head;
	}
	
	fifo->head = entry;
    fifo->size++;

    return fifo->size;
}

bool Fifo_empty(PFifo fifo)
{
    return fifo->size == 0;
}

size_t Fifo_size(PFifo fifo)
{
    return fifo->size;
}

PFifoEntry Fifo_front(PFifo fifo)
{
    if (fifo->size == 0)
        return NULL;

    return fifo->front;
}

bool Fifo_pop_front(PFifo fifo)
{
#ifdef DEBUG_PRINT
    printf("Fifo_pop_front\n");
#endif
	PFifoEntry f;
    if (fifo->size == 0)
    {
#ifdef DEBUG_PRINT
        printf(" - size is 0\n");
#endif
        return false;
    }

	f = fifo->front;
	fifo->front = f->next;
    //if ( f->next != NULL)
	    //f->next->last = NULL;

    free(f);

    fifo->size--;
    
	return true;
}
