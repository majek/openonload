/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
**  \brief  TCPDirect API for attribute objects
*//*
\**************************************************************************/

#ifndef __ZF_ATTR_H__
#define __ZF_ATTR_H__

#ifndef __IN_ZF_TOP_H__
# error "Please include zf.h to use TCPDirect."
#endif


/*! \struct zf_attr
**
** \brief Attribute object.
**
** Attributes are used to specify optional behaviours and parameters,
** usually when allocating objects.  Each attribute object defines a
** complete set of the attributes that the stack understands.
**
** For example, the "max_udp_rx_endpoints" attribute controls how many
** UDP-receive zockets can be created per zf_stack.
**
** The default values for attributes may be overridden by setting the
** environment variable ZF_ATTR.  For example:
**
** ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
** ZF_ATTR="interface=enp4s0f0;log_level=3"
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


/*! \brief Allocate an attribute object.
**
** \param attr_out   The attribute object is returned here.
**
** \return 0 on success, or a negative error code:\n
**         -ENOMEM if memory could not be allocated\n
**         -EINVAL if the ZF_ATTR environment variable is malformed.
*/
ZF_LIBENTRY int  zf_attr_alloc(struct zf_attr** attr_out);

/*! \brief Free an attribute object.
**
** \param attr       The attribute object.
*/
ZF_LIBENTRY void zf_attr_free(struct zf_attr* attr);

/*! \brief Return attributes to their default values.
**
** \param attr       The attribute object.
*/
ZF_LIBENTRY void zf_attr_reset(struct zf_attr* attr);

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
ZF_LIBENTRY int zf_attr_set_int(struct zf_attr* attr,
                           const char* name, int64_t val);

/*! \brief Get an integer-valued attribute.
**
** \param attr       The attribute object.
** \param name       Name of the attribute.
** \param val        Value of the attribute (output).
**
** \return 0 on success, or a negative error code:
**         -ENOENT if @p name is not a valid attribute name
**         -EINVAL if @p name does not have an integer type
*/
ZF_LIBENTRY int zf_attr_get_int(struct zf_attr* attr,
                           const char* name, int64_t* val);

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
ZF_LIBENTRY int zf_attr_set_str(struct zf_attr* attr,
                           const char* name, const char* val);

/*! \brief Get a string-valued attribute.
**
** \param attr       The attribute object.
** \param name       Name of the attribute.
** \param val        Value of the attribute (output). This may be NULL.
**                   This is allocated with strdup() and must be free()ed by
**                   the caller.
**
** \return 0 on success, or a negative error code:
**         -ENOENT if @p name is not a valid attribute name
**         -EINVAL if @p name does not have a string type
**         -ENOMEM if strdup failed to duplicate the string value
*/
ZF_LIBENTRY int zf_attr_get_str(struct zf_attr* attr,
                           const char* name, char** val);

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
ZF_LIBENTRY int zf_attr_set_from_str(struct zf_attr* attr,
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
ZF_LIBENTRY int zf_attr_set_from_fmt(struct zf_attr* attr,
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
ZF_LIBENTRY struct zf_attr* zf_attr_dup(const struct zf_attr* attr);

/*! \brief Returns documentation for an attribute, or names of all attributes.
**
** \param attr_name_opt     The attribute name.
** \param docs_out          On success, a pointer to an array of pointers to
**                          doc strings.
** \param docs_len_out      On success, the number of entries in @p docs_out.
**
** \return 0 on success, or a negative error code.
**
** This function returns pointers to the documentation for an attribute, or
** to the names of all attributes.
**
** If @p attr_name_opt is the name of an attribute, the array referenced by
** @p docs_out contains the following strings in order:
** - the name of the attribute
** - the type of the attribute (e.g. "int", "str")
** - the status of the attribute (e.g. "stable", "hidden", "beta")
** - a description of the default value of the attribute
** - the type(s) of objects the attribute applies to (e.g. "zf_stack",
**   "zf_pool", "zf_vi")
** - a description of the attribute.
**
** If @p attr_name_opt is NULL or the empty string, the array referenced by
** @p docs_out instead contains all attribute names.
**
** After calling this function, the memory it allocates for pointers must be
** freed by calling free(docs_out).
*/
ZF_LIBENTRY int zf_attr_doc(const char* attr_name_opt,
                       const char*** docs_out, int* docs_len_out);

#endif  /* __ZF_ATTR_H__ */
/** @} */
