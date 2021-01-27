/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <snort/snort.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} snort_deq_trace_t;

static u8 *
format_snort_deq_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  snort_deq_trace_t *t = va_arg (*args, snort_deq_trace_t *);

  s = format (s, "snort-deq: sw_if_index %d, next index %d\n", t->sw_if_index,
	      t->next_index);

  return s;
}

#define foreach_snort_deq_error                                               \
  _ (BAD_DESC, "bad descriptor")                                              \
  _ (BAD_DESC_INDEX, "bad descriptor index")

typedef enum
{
#define _(sym, str) SNORT_DEQ_ERROR_##sym,
  foreach_snort_deq_error
#undef _
    SNORT_DEQ_N_ERROR,
} snort_deq_error_t;

static char *snort_deq_error_strings[] = {
#define _(sym, string) string,
  foreach_snort_deq_error
#undef _
};

static_always_inline uword
snort_deq_instance (vlib_main_t *vm, u32 instance_index, u32 *buffer_indices,
		    u16 *nexts, u32 max_recv)
{
  snort_main_t *sm = &snort_main;
  snort_per_thread_data_t *ptd =
    vec_elt_at_index (sm->per_thread_data, vm->thread_index);
  snort_instance_t *si = vec_elt_at_index (sm->instances, instance_index);
  snort_qpair_t *qp = vec_elt_at_index (si->qpairs, vm->thread_index);
  u32 mask = pow2_mask (qp->log2_queue_size);
  u32 head, next, n_recv = 0, n_left;

  head = __atomic_load_n (qp->deq_head, __ATOMIC_ACQUIRE);
  next = qp->next_desc;

  n_left = (head - next) & mask;

  if (n_left == 0)
    return 0;

  if (n_left > max_recv)
    {
      n_left = max_recv;
      clib_interrupt_set (ptd->interrupts, instance_index);
      vlib_node_set_interrupt_pending (vm, snort_deq_node.index);
    }

  while (n_left)
    {
      u32 desc_index, bi;
      daq_vpp_desc_t *d;

      /* check if descriptor index taken from dequqe ring is valid */
      if ((desc_index = qp->deq_ring[next]) & ~mask)
	{
	  vlib_node_increment_counter (vm, snort_deq_node.index,
				       SNORT_DEQ_ERROR_BAD_DESC_INDEX, 1);
	  goto next;
	}

      /* check if descriptor index taken from dequeue ring points to enqueued
       * buffer */
      if ((bi = qp->buffer_indices[desc_index]) == ~0)
	{
	  vlib_node_increment_counter (vm, snort_deq_node.index,
				       SNORT_DEQ_ERROR_BAD_DESC, 1);
	  goto next;
	}

      /* put descriptor back to freelist */
      vec_add1 (qp->freelist, desc_index);
      d = qp->descriptors + desc_index;
      buffer_indices++[0] = bi;
      if (d->action == DAQ_VPP_ACTION_FORWARD)
	nexts[0] = qp->next_indices[desc_index];
      else
	nexts[0] = SNORT_ENQ_NEXT_DROP;
      qp->buffer_indices[desc_index] = ~0;
      nexts++;
      n_recv++;

      /* next */
    next:
      next = (next + 1) & mask;
      n_left--;
    }

  qp->next_desc = next;

  return n_recv;
}

VLIB_NODE_FN (snort_deq_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  snort_main_t *sm = &snort_main;
  snort_per_thread_data_t *ptd =
    vec_elt_at_index (sm->per_thread_data, vm->thread_index);
  u32 buffer_indices[VLIB_FRAME_SIZE], *bi = buffer_indices;
  u16 next_indices[VLIB_FRAME_SIZE], *nexts = next_indices;
  u32 n_left = VLIB_FRAME_SIZE, n;
  int inst = -1;

  while ((inst = clib_interrupt_get_next (ptd->interrupts, inst)) != -1)
    {
      clib_interrupt_clear (ptd->interrupts, inst);
      n = snort_deq_instance (vm, inst, bi, nexts, n_left);
      n_left -= n;
      bi += n;
      nexts += n;

      if (n_left == 0)
	goto enq;
    }

  if (n_left == VLIB_FRAME_SIZE)
    return 0;

enq:
  n = VLIB_FRAME_SIZE - n_left;
  vlib_buffer_enqueue_to_next (vm, node, buffer_indices, next_indices, n);
  return n;
}

VLIB_REGISTER_NODE (snort_deq_node) = {
  .name = "snort-deq",
  .vector_size = sizeof (u32),
  .format_trace = format_snort_deq_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .sibling_of = "snort-enq",

  .n_errors = ARRAY_LEN (snort_deq_error_strings),
  .error_strings = snort_deq_error_strings,

  .n_next_nodes = 0,
};
