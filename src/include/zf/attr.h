/*
** Copyright 2005-2016  Solarflare Communications Inc.
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
** \author  mj
**  \brief  ZF Attr API
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ZF_ATTR_H__
#define __ZF_ATTR_H__

#include <zf/zf_platform.h>


/*! \struct zf_attr
**
** \brief Attribute object.
**
** Attributes are used to specify optional behaviours and parameters,
** usually when allocating objects.  Each attribute object defines a
** complete set of the attributes that the stack understands.
**
** For example, the "endpoint_max" attribute controls which how many
** sockets can be created per zf_stack.
**
** The default values for attributes may be overridden by setting the
** environment variable ZF_ATTR.  For example:
**
** ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
** ZF_ATTR="log_level=3;snap=2"
** ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
**
** Each function that takes an attribute argument will only be interested
** in a subset of the attributes specified by an zf_attr instance.  Other
** attributes are ignored.
**
** The set of attributes supported may change between releases, so
** applications should where possible tolerate failures when setting
** attributes.
*/
struct zf_attr;


/*! \struct zf_object
**
** \brief Attribute object.
**
** TBD
*/


/*! \brief Allocate an attribute object.
**
** \param attr_out   The attribute object is returned here.
**
** \return 0 on success, or a negative error code:\n
**         -ENOMEM if memory could not be allocated\n
**         -EINVAL if the ZF_ATTR environment variable is malformed.
*/
LIBENTRY int  zf_attr_alloc(struct zf_attr** attr_out);

/*! \brief Free an attribute object.
**
** \param attr       The attribute object.
*/
LIBENTRY void zf_attr_free(struct zf_attr* attr);

/*! \brief Return attributes to their default values.
**
** \param attr       The attribute object.
*/
LIBENTRY void zf_attr_reset(struct zf_attr* attr);

/*! \brief Set an attribute to an integer value.
**
** \param attr       The attribute object.
** \param name       Name of the attribute.
** \param val        New value for the attribute.
**
** \return 0 on success, or a negative error code:\n
**         -ENOENT if @p name is not a valid attribute name\n
**         -EOVERFLOW if @p val is not within the range of values this
**                    attribute can take.
*/
LIBENTRY int zf_attr_set_int(struct zf_attr* attr,
                           const char* name, int64_t val);

/*! \brief Set an attribute to a string value.
**
** \param attr       The attribute object.
** \param name       Name of the attribute.
** \param val        New value for the attribute (may be NULL).
**
** \return 0 on success, or a negative error code:\n
**         -ENOENT if @p name is not a valid attribute name\n#
**         -ENOMSG if the attribute is not a string attribute.
*/
LIBENTRY int zf_attr_set_str(struct zf_attr* attr,
                           const char* name, const char* val);

/*! \brief Set an attribute from a string value.
**
** \param attr       The attribute object.
** \param name       Name of the attribute.
** \param val        New value for the attribute.
**
** \return 0 on success, or a negative error code:\n
**         -ENOENT if @p name is not a valid attribute name\n
**         -EINVAL if it is not possible to convert @p val to a valid value
**                 for the attribute\n
**         -EOVERFLOW if @p val is not within the range of values this
**                    attribut can take.
*/
LIBENTRY int zf_attr_set_from_str(struct zf_attr* attr,
                                const char* name, const char* val);

/*! \brief Set an attribute to a string value (with formatting).
**
** \param attr       The attribute object.
** \param name       Name of the attribute.
** \param fmt        Format string for the new attribute value.
**
** \return 0 on success, or a negative error code:\n
**         -ENOENT if @p name is not a valid attribute name\n
**         -EINVAL if it is not possible to convert @p fmt to a valid value
**                 for the attribute\n
**         -EOVERFLOW if @p fmt is not within the range of values this
**                    attribut can take.
**
** This function behaves exactly as zf_attr_set_from_str(), except that the
** string value is generated from a printf()-style format string.
*/
LIBENTRY int zf_attr_set_from_fmt(struct zf_attr* attr,
                                const char* name, const char* fmt, ...);

/*! \brief Duplicate an attribute object.
**
** \param attr       The attribute object.
**
** \return           A new attribute object.
**
** This function is useful when you want to make non-destructive changes to
** an existing attribute object.
*/
LIBENTRY struct zf_attr* zf_attr_dup(const struct zf_attr* attr);

/*! \brief Returns documentation for an attribute.
**
** \param attr_name_opt     The attribute name.
** \param docs_out          On success, the resulting doc string output.
** \param docs_len_out      On success, the length of the doc string output.
**
** \return 0 on success, or a negative error code.
*/
LIBENTRY int zf_attr_doc(const char* attr_name_opt,
                       const char*** docs_out, int* docs_len_out);

/*! \brief Convert an ::zf_attr to an ::zf_object.
**
** \param attr            An ::zf_attr instance or NULL
**
** \return                The ::zf_object on success, or NULL on any error,
**                        including the following:\n
**                        @p attr is NULL.
*/
LIBENTRY struct zf_object* zf_attr_to_object(const struct zf_attr* attr);

/*! \brief Convert an ::zf_object to an ::zf_attr.
**
** \param obj             An ::zf_object instance or NULL
**
** \return                The ::zf_attr on success, or NULL on any error,
**                        including the following:\n
**                        @p obj is NULL\n
**                        @p obj is not of type ZF_OBJ_C_ATTR.
*/
LIBENTRY const struct zf_attr* zf_attr_from_object(struct zf_object* obj);

#endif  /* __ZF_ATTR_H__ */
