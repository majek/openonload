/*
** Copyright 2005-2014  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of version 2 of the GNU General Public License as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  
**  \brief  Linked list.
**   \date  2002/08/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_SLLIST_H__
#define __CI_TOOLS_SLLIST_H__


typedef struct ci_sllink_s {
  struct ci_sllink_s*  next;
} ci_sllink;


typedef struct {
  ci_sllink*  head;
} ci_sllist;

/**********************************************************************/

ci_inline void ci_sllist_init(ci_sllist* list)
{ list->head = 0; }


ci_inline int ci_sllist_is_empty(ci_sllist* list)
{ return list->head == 0; }

ci_inline int ci_sllist_not_empty(ci_sllist* list)
{ return list->head != 0; }


ci_inline void ci_sllist_push(ci_sllist* list, ci_sllink* link) {
  link->next = list->head;
  list->head = link;
}


ci_inline ci_sllink* ci_sllist_pop(ci_sllist* list) {
  ci_sllink* link;
  link = list->head;
  list->head = link->next;
  return link;
}


ci_inline ci_sllink* ci_sllist_try_pop(ci_sllist* list) {
  ci_sllink* link;
  if( (link = list->head) )  list->head = link->next;
  return link;
}

#define CI_SLLIST_TRY_POP(c_type, lnk_mbr, list)			  \
  ((list)->head ? CI_CONTAINER(c_type, lnk_mbr, ci_sllist_pop(list)) : NULL)


ci_inline void ci_sllist_insert_after(ci_sllink* before, ci_sllink* after) {
  after->next = before->next;
  before->next = after;
}

/**********************************************************************/

/*
** The following two macros implement a for(...) loop that iterates over
** the members of the list.  If the loop completes, then the iterator
** [p_lnk] or [p_c] is set to null.
*/

#define CI_SLLIST_FOR_EACH(p_lnk, p_list)				 \
  for( (p_lnk) = (p_list)->head; (p_lnk) != 0; (p_lnk) = (p_lnk)->next )

#define CI_SLLIST_FOR_EACH2(c_type, p_c, lnk_mbr, p_list)		\
  for( (p_c) = (p_list)->head ?						\
	 CI_CONTAINER(c_type, lnk_mbr, (p_list)->head) : 0;		\
       (p_c) != 0;							\
       (p_c) = ((p_c)->lnk_mbr).next ?					\
	 CI_CONTAINER(c_type, lnk_mbr, ((p_c)->lnk_mbr).next) : 0 )


#endif  /* __CI_TOOLS_SLLIST_H__ */
/*! \cidoxg_end */
