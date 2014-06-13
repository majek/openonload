/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
** \author  cgg
**  \brief  Version counter locking definitions
**   \date  2005/07/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal_cplane_types */

/*! This header provides support for the \c ci_verlock_t type which can be
 *  used to implement a cheap read-lock suitable for use in circumstances
 *  where the protected datastructure is rarely updated
 *
 *  Example use:
 *
 *  struct protected
 *  {   some_lock_t writelock; // if simultaneous writes are possible 
 *      ci_verlock_t readlock;
 *      int field1;
 *      void *field2;
 *      char field3;
 *  };
 *
 *  static void update_it(struct protected *data, void *f2, char f3)
 *  {
 *      openlock(data->writelock); // to protect against simultaneous writes
 *      
 *      CI_VERLOCK_WRITE_BEGIN(data->readlock)
 *          data->field1++;
 *          data->field2 = f2;
 *          data->field3 = f3;
 *      CI_VERLOCK_WRITE_END(data->readlock)
 *
 *      closelock(data->writelock);
 *  }
 *
 *
 *  static void read_it(struct protected *data)
 *  {   int f1;
 *      void *f2;
 *
 *      CI_VERLOCK_READ_BEGIN(data->readlock)
 *          // note: definitions placed here are not visible outside this block
 *          // warning - code in this area may be executed many times
 *          //           the average number of times will be proportional to
 *          //           the amount of code included in this block
 *          f1 = data->field1;
 *          f2 = data->field2;
 *      CI_VERLOCK_READ_END(data->readlock)
 *
 *      // Here we can guarantee that f1 and f2 come from the same version
 *      // of 'data', even when update_it and read_it can be called
 *      // simultaneously
 *      ...
 * }
 */

#ifndef __ONLOAD_VERLOCK_H__
#define __ONLOAD_VERLOCK_H__

#ifdef __cplusplus
extern "C" {
#endif


/* NB: really we'd like to do something that will prevent the compiler
 * re-ordering this call with respect to surrounding code
 */
ci_inline ci_verlock_value_t ci_verlock_get(const ci_verlock_t *ref_lock)
{   ci_verlock_value_t value = *ref_lock;
    ci_rmb(); /* make sure subsquent reads occur after the version is taken */ 
    return value;
}


ci_inline int /* bool */ ci_verlock_unchanged(const ci_verlock_t *ref_lock,
					      ci_verlock_value_t value)
{   ci_rmb(); /* to stop version being checked before a previous update */
    return (*ref_lock == value);
}


ci_inline int /* bool */ ci_verlock_updating(const ci_verlock_t *ref_lock)
{   return ((*ref_lock & 1)==0);
}


/* Macros for bracketing a version-protected read that may spin forever */

#define CI_VERLOCK_READ_BEGIN(_lock)                                    \
        {   ci_verlock_value_t _version;                                \
            ci_verlock_value_t _nextver = _lock;                        \
            ci_rmb(); /* make sure lock read before fields */           \
            do								\
            {   _version = _nextver;			                \
                {
		
#define CI_VERLOCK_READ_END(_lock)                                      \
                }							\
                ci_rmb(); /* make sure lock re-read after fields */     \
                _nextver = _lock;                                       \
	    } while (CI_UNLIKELY(_nextver != _version ||                \
                                 ci_verlock_updating(&_version)));      \
	}

#define CI_VERLOCK_READ(_lock, _read_code)                              \
        {   CI_VERLOCK_READ_BEGIN(_lock)                                \
            _read_code;                                                 \
            CI_VERLOCK_READ_END(_lock)                                  \
        }


/* Macros for bracketing a version-protected read that tries only once */

#define CI_VERLOCK_READ_NOW_BEGIN(_lock)                                \
        {   ci_verlock_value_t version = _lock;                         \
            ci_rmb(); /* make sure lock read before fields */           \
            if (CI_LIKELY(!ci_verlock_updating(&version)))              \
            {                                                           \
		{                                                       \

#define CI_VERLOCK_READ_NOW_END(_lock, _was_read)                       \
                }							\
                ci_rmb(); /* make sure lock re-read after fields */     \
                _was_read = ((_lock) == version);                       \
	    } else                                                      \
                _was_read = 0 /* false */;                              \
	}

#define CI_VERLOCK_READ_NOW(_lock, _was_read, _read_code)               \
        {   CI_VERLOCK_READ_NOW_BEGIN(_lock)                            \
            _read_code;                                                 \
            CI_VERLOCK_READ_NOW_END(_lock, _was_read)                   \
        }


/* Macros for bracketing a version-protected read that retries N times */

#define CI_VERLOCK_READ_SOON_BEGIN(_lock, max_attempts)                 \
        {   ci_verlock_value_t version;                                 \
            ci_verlock_value_t _nextver = _lock;                        \
            int tries_left = max_attempts;                              \
            ci_rmb(); /* make sure lock read before fields */           \
            do								\
            {   version = _nextver;			                \
                {
		
#define CI_VERLOCK_READ_SOON_END(_lock, _was_read)                      \
                }							\
                ci_rmb(); /* make sure lock reread after fields */      \
                _nextver = _lock;					\
                was_read = (_nextver == version &&                      \
			    !ci_verlock_updating(&version));            \
	    } while (CI_UNLIKELY(!_was_read && tries_left-- > 0));	\
	}

#define CI_VERLOCK_READ_SOON(_lock, _was_read, _attempts, _read_code)   \
        {   CI_VERLOCK_READ_SOON_BEGIN(_lock, _attempts)                \
            _read_code;                                                 \
            CI_VERLOCK_READ_SOON_END(_lock, _was_read)                  \
        }



ci_inline void _ci_verlock_odd_succ(ci_verlock_t *ref_lock)
{   if (*ref_lock == (ci_verlock_value_t)(CI_VERLOCK_BAD-1))
        *ref_lock += 3;
    else
        (*ref_lock)++;
    
    ci_assert_nequal(CI_VERLOCK_BAD, *ref_lock);
    /* this should never happen, unless a third party updated the lock
       between the test and the increment above - this ought to have been
       prevented through the use of a surrouding write lock
    */
}
     
ci_inline void _ci_verlock_even_succ(ci_verlock_t *ref_lock)
{   (*ref_lock)++;
}

/*! bump the version number to the next "valid" version number */
ci_inline void ci_verlock_invalidate(ci_verlock_t *ref_lock)
{   *ref_lock += 2;
}

/*! move the version number to an "invalid" version number from a valid one */
ci_inline void ci_verlock_write_start(ci_verlock_t *ref_lock)
{   _ci_verlock_odd_succ(ref_lock);

    /* ensure the hardware has written out the even lock before any other
       writes take place + ensure successive reads follow this */
    ci_mb();
}

/*! move the version number to a "valid" version number from an invalid one */
ci_inline void ci_verlock_write_stop(ci_verlock_t *ref_lock)
{   /* ensure we never see an odd lock before the hardware has
       finished the writes that preceed this */
    ci_wmb();
    
    _ci_verlock_even_succ(ref_lock);
}


/* Macros for bracketing a version-protected write */

#define CI_VERLOCK_WRITE_BEGIN(lock)                                    \
        ci_verlock_write_start(&lock); {
		
#define CI_VERLOCK_WRITE_END(lock)                                      \
        } ci_verlock_write_stop(&lock);

#define CI_VERLOCK_WRITE(_lock, _write_code)                            \
        {   CI_VERLOCK_WRITE_BEGIN(_lock)                               \
                _write_code;                                                \
            CI_VERLOCK_WRITE_END(_lock)                                 \
        }


#ifdef __cplusplus
}
#endif

#endif /* __ONLOAD_VERLOCK_H__ */
