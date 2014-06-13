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

/****************************************************************************
 * Java linkage for onload extention library.
 *
 * Copyright 2007-2012: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications <linux-net-drivers@solarflare.com>
 *
 ****************************************************************************
 */

#include <jni.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "extensions.h"
#include "extensions_zc.h"

#include "OnloadExt.h"
#include "OnloadZeroCopy.h"
#include "OnloadTemplateSend.h"

struct native_zc_userdata {
	JNIEnv*	env;
	jobject	cb;
	int fd;
};

static char* JNU_GetStringNativeChars(JNIEnv *env, jstring jstr);

JNIEXPORT jint JNICALL
Java_OnloadExt_SaveStackName (JNIEnv* env, jclass cls)
{
	(void) env;
	(void) cls;
	return (jint) onload_stackname_save();
}

JNIEXPORT jint JNICALL
Java_OnloadExt_RestoreStackName (JNIEnv* env, jclass cls)
{
	return (jint) onload_stackname_restore();
}

JNIEXPORT jint JNICALL
Java_OnloadExt_SetStackOption (JNIEnv* env, jclass cls,
				jstring option, jint opt_val )
{
	int64_t val = opt_val;
	char* opt = JNU_GetStringNativeChars(env, option);
	jint rval;
	(void) cls;

	if ( !opt )
		return -EINVAL;

	rval = (jint) onload_stack_opt_set_int( opt, val );
	free(opt);
	return rval;
}

JNIEXPORT jint JNICALL
Java_OnloadExt_ResetStackOptions (JNIEnv* env, jclass cls)
{
	(void) env;
	(void) cls;
	return (jint) onload_stack_opt_reset();
}


/* ******************************************************** */
/* Checking that java constants are the same as C constants */
/* ******************************************************** */

#define CHECK_CONSTANT(_x) ( _x == OnloadExt_##_x )
#define CHECK_CONSTANT_ZC(_x) ( _x == OnloadZeroCopy_##_x )
#define CHECK_CONSTANT_TMPL(_x) ( _x == OnloadTemplateSend_##_x )

static int AreContstantsOk()
{
	/* TODO: Make this a compile-time check */
	/* TODO: Better still, make the creation of these defines automatic so
	   we don't need any check at all. */
	/* Of especial concern are ONLOAD_MSG_DONTWAIT ONLOAD_MSG_NOSIGNAL and
	   ONLOAD_MSG_NOSIGNAL which are actually #define and indirectly come
	   from the sockets API.
	   If we can use the same constants java side and C side, we can avoid
	   a translation step so check that. */
	return CHECK_CONSTANT(ONLOAD_SCOPE_NOCHANGE)
	&& CHECK_CONSTANT(ONLOAD_SCOPE_THREAD)
	&& CHECK_CONSTANT(ONLOAD_SCOPE_PROCESS)
	&& CHECK_CONSTANT(ONLOAD_SCOPE_USER)
	&& CHECK_CONSTANT(ONLOAD_SCOPE_GLOBAL)
	&& CHECK_CONSTANT(ONLOAD_THIS_THREAD)
	&& CHECK_CONSTANT(ONLOAD_ALL_THREADS)
	&& CHECK_CONSTANT(ONLOAD_SPIN_ALL)
	&& CHECK_CONSTANT(ONLOAD_SPIN_UDP_RECV)
	&& CHECK_CONSTANT(ONLOAD_SPIN_UDP_SEND)
	&& CHECK_CONSTANT(ONLOAD_SPIN_TCP_RECV)
	&& CHECK_CONSTANT(ONLOAD_SPIN_TCP_SEND)
	&& CHECK_CONSTANT(ONLOAD_SPIN_TCP_ACCEPT)
	&& CHECK_CONSTANT(ONLOAD_SPIN_PIPE_RECV)
	&& CHECK_CONSTANT(ONLOAD_SPIN_PIPE_SEND)
	&& CHECK_CONSTANT(ONLOAD_SPIN_SELECT)
	&& CHECK_CONSTANT(ONLOAD_SPIN_POLL)
	&& CHECK_CONSTANT(ONLOAD_SPIN_PKT_WAIT)
	&& CHECK_CONSTANT(ONLOAD_SPIN_EPOLL_WAIT)
	&& CHECK_CONSTANT(ONLOAD_FD_FEAT_MSG_WARM)
	&& CHECK_CONSTANT_ZC(ONLOAD_MSG_RECV_OS_INLINE)
	&& CHECK_CONSTANT_ZC(ONLOAD_MSG_DONTWAIT)
	&& CHECK_CONSTANT_ZC(ONLOAD_ZC_MSG_SHARED)
	&& CHECK_CONSTANT_ZC(ONLOAD_ZC_END_OF_BURST)
	&& CHECK_CONSTANT_ZC(ONLOAD_ZC_CONTINUE)
	&& CHECK_CONSTANT_ZC(ONLOAD_ZC_TERMINATE)
	&& CHECK_CONSTANT_ZC(ONLOAD_ZC_KEEP)
	&& CHECK_CONSTANT_ZC(ONLOAD_ZC_MODIFIED)
	&& CHECK_CONSTANT_ZC(ONLOAD_ZC_BUFFER_HDR_NONE)
	&& CHECK_CONSTANT_ZC(ONLOAD_ZC_BUFFER_HDR_UDP)
	&& CHECK_CONSTANT_ZC(ONLOAD_ZC_BUFFER_HDR_TCP)
	&& CHECK_CONSTANT_ZC(ONLOAD_MSG_NOSIGNAL)
	&& CHECK_CONSTANT_ZC(ONLOAD_MSG_NOSIGNAL)
	&& CHECK_CONSTANT_TMPL(ONLOAD_TEMPLATE_FLAGS_SEND_NOW)
	&& CHECK_CONSTANT_TMPL(ONLOAD_TEMPLATE_FLAGS_DONTWAIT)
	;
}

/* ***************** */
/* Utility functions */
/* ***************** */

static jstring JNU_NewStringNative(JNIEnv *env, const char *str)
{
	/* TODO: These should be cachable between invocations */
	jclass Class_java_lang_String;
	jmethodID MID_String_init;
	int len;
	jstring result = NULL;
	jbyteArray bytes = 0;
	
	Class_java_lang_String = (*env)->FindClass(env,"java/lang/String");
	if ( !Class_java_lang_String )
		return NULL;

	MID_String_init = (*env)->GetMethodID(env, Class_java_lang_String,
						"<init>", "([B)V" );
	if ( !MID_String_init )
		return NULL;

#if JNI_VERSION_1_2
	/* Out of memory check, JDK1.2+ only */
	if ((*env)->EnsureLocalCapacity(env, 2) < 0) {
		return NULL;
	}
#endif	/* JNI_VERSION_1_2 */
	len = strlen(str);
	bytes = (*env)->NewByteArray(env, len);
	if ( bytes != NULL && !(*env)->ExceptionOccurred(env) ) {
		(*env)->SetByteArrayRegion(env, bytes, 0, len, (jbyte *)str);
		if ( !(*env)->ExceptionOccurred(env) )
			result = (jstring) (*env)->NewObject(env,
				Class_java_lang_String, MID_String_init, bytes);
		(*env)->DeleteLocalRef(env, bytes);
	}
	return result;
}

static char* JNU_GetStringNativeChars(JNIEnv *env, jstring jstr)
{
	/* TODO: These should be cachable between invocations */
	jclass Class_java_lang_String;
	jmethodID MID_String_getBytes;
	jthrowable exc;
	jbyteArray bytes = 0;
	char *result = 0;
	
	Class_java_lang_String = (*env)->FindClass(env,"java/lang/String");
	if ( !Class_java_lang_String )
		return NULL;

	MID_String_getBytes = (*env)->GetMethodID( env, Class_java_lang_String,
							"getBytes", "()[B" );
	if ( !MID_String_getBytes )
		return NULL;

#if JNI_VERSION_1_2
	if ((*env)->EnsureLocalCapacity(env, 2) < 0) {
		return 0; /* out of memory error */
	}
#endif	/* JNI_VERSION_1_2 */
	bytes = (*env)->CallObjectMethod(env, jstr, MID_String_getBytes);
	exc = (*env)->ExceptionOccurred(env);
	if (!exc) {
		jint len = (*env)->GetArrayLength(env, bytes);
		result = (char *)malloc((size_t)len + 1);
		if (result == 0) {
			JNU_ThrowByName(env, "java/lang/OutOfMemoryError", 0);
			(*env)->DeleteLocalRef(env, bytes);
			return 0;
		}
		(*env)->GetByteArrayRegion(env, bytes, 0, len, (jbyte *)result);
		result[len] = 0; /* NULL-terminate */
	} else {
		(*env)->DeleteLocalRef(env, exc);
	}
	(*env)->DeleteLocalRef(env, bytes);
	return result;
}

static jboolean IsInstanceOf( JNIEnv *env, jobject obj, char const* class_name )
{
	jclass classId;
	classId = (*env)->FindClass( env, class_name );
	if ( !classId )
		return JNI_FALSE;
	return (*env)->IsInstanceOf( env, obj, classId );
}

static jobject GetFieldFromObject( JNIEnv *env, jobject obj, char const* field,
					char const* field_type )
{
	jclass classId;
	jfieldID fieldId;
	if ( !obj )
		return NULL;
	classId = (*env)->GetObjectClass(env, obj);
	if ( !classId )
		return NULL;
	fieldId = (*env)->GetFieldID(env, classId, field, field_type );
	if ( !fieldId )
		return NULL;
	return (*env)->GetObjectField( env, obj, fieldId );
}

static jobject CreateObject( JNIEnv* env, char const* sig )
{
	jclass classId = (*env)->FindClass(env, sig);
	if ( !classId )
		return NULL;
	jmethodID initId = (*env)->GetMethodID(env, classId, "<init>", "()V" );

	if ( !initId )
		return NULL;
	return (*env)->NewObject( env, classId, initId );
}

static jobject RunMethodOnObject( JNIEnv *env, jobject obj, char const* field,
					char const* field_type )
{
	jclass classId;
	jmethodID methodId;
	if ( !obj )
		return NULL;
	classId = (*env)->GetObjectClass(env, obj);
	if ( !classId )
		return NULL;
	methodId = (*env)->GetMethodID(env, classId, field, field_type );
	if ( !methodId )
		return NULL;
	return (*env)->CallNonvirtualObjectMethod(env, obj, classId, methodId );
}

static jint GetIntFromObject( JNIEnv *env, jobject obj, char const* field )
{
	jclass classId;
	jfieldID fieldId;

	if ( !obj )
		return 0;
	classId = (*env)->GetObjectClass(env, obj);
	if ( !classId )
		return 0;
	fieldId = (*env)->GetFieldID(env, classId, field, "I" );
	if ( !fieldId )
		return 0;

	return (*env)->GetIntField( env, obj, fieldId );
}

static void SetIntOnObject( JNIEnv *env, jobject obj, char const* field,
				jint value )
{
	jclass classId;
	jfieldID fieldId;

	if ( !obj )
		return;
	classId = (*env)->GetObjectClass(env, obj);
	if ( !classId )
		return;
	fieldId = (*env)->GetFieldID(env, classId, field, "I" );
	if ( !fieldId )
		return;

	return (*env)->SetIntField( env, obj, fieldId, value );
}

static jlong GetLongFromObject( JNIEnv *env, jobject obj, char const* field )
{
	jclass classId;
	jfieldID fieldId;

	if ( !obj )
		return 0;
	classId = (*env)->GetObjectClass(env, obj);
	if ( !classId )
		return 0;
	fieldId = (*env)->GetFieldID(env, classId, field, "J" );
	if ( !fieldId )
		return 0;

	return (*env)->GetLongField( env, obj, fieldId );
}

static void SetLongOnObject( JNIEnv *env, jobject obj, char const* field,
				jlong value )
{
	jclass classId;
	jfieldID fieldId;

	if ( !obj )
		return;
	classId = (*env)->GetObjectClass(env, obj);
	if ( !classId )
		return;
	fieldId = (*env)->GetFieldID(env, classId, field, "J" );
	if ( !fieldId )
		return;

	return (*env)->SetLongField( env, obj, fieldId, value );
}

static void SetObjectOnObject( JNIEnv *env, jobject obj, char const* field,
				char const* field_type, jobject value )
{
	jclass classId;
	jfieldID fieldId;

	if ( !obj )
		return;
	classId = (*env)->GetObjectClass(env, obj);
	if ( !classId )
		return;
	fieldId = (*env)->GetFieldID(env, classId, field, field_type );
	if ( !fieldId )
		return;

	return (*env)->SetObjectField( env, obj, fieldId, value );
}

static jobject GetObjectFromObject( JNIEnv *env, jobject obj, char const* field,
					char const* field_type )
{
	jclass classId;
	jfieldID fieldId;

	if ( !obj )
		return NULL;
	classId = (*env)->GetObjectClass(env, obj);
	if ( !classId )
		return NULL;
	fieldId = (*env)->GetFieldID(env, classId, field, field_type );
	if ( !fieldId )
		return NULL;

	return (*env)->GetObjectField( env, obj, fieldId );
}

static jobject
NewZcBuffer( JNIEnv* env, struct onload_zc_iovec* iovec, int fd )
{
	jlong opaque = (jlong) iovec->buf;
	jobject bb = (*env)->NewDirectByteBuffer(env, iovec->iov_base,
						iovec->iov_len);
	if ( !bb ) return 0;
	jobject rval = CreateObject( env, "OnloadZeroCopy" );
	if ( !rval ) return 0;
	
	SetIntOnObject( env, rval, "associated_fd", fd );
	SetLongOnObject( env, rval, "opaque", opaque );
	SetObjectOnObject( env, rval, "buffer", "Ljava/nio/ByteBuffer;", bb );

	return rval;
};

/* ****************************** */
/* Native privacy defying methods */
/* ****************************** */
/* NOTE: This code is using some pretty horrible private methods
   to get the information it needs.  Ideally, call in with a
   FileDescriptor rather than a socket, or be prepared to rewrite this
   if you use a different class library or VM.
   Use "javap -private" liberally to find the underlying file
   descriptor location if it moves. */
static jint GetFdFromFileDescriptor( JNIEnv *env, jobject obj )
{
	return GetIntFromObject( env, obj, "fd" );
}

static int GetFdFromObject( JNIEnv *env, jobject obj, char const* implType )
{
	jobject impl;
	jobject desc;
	
	if ( !obj )
		return -EINVAL;
	
	impl = RunMethodOnObject( env, obj, "getImpl", implType );
	if ( !impl )
		return -EINVAL;

	desc = RunMethodOnObject( env, impl, "getFileDescriptor",
					"()Ljava/io/FileDescriptor;" );
	if ( !desc )
		return -EINVAL;

	return GetFdFromFileDescriptor( env, desc );
}

static int GetFdFromDatagramSocket( JNIEnv *env, jobject obj )
{
	return GetFdFromObject( env, obj, "()Ljava/net/DatagramSocketImpl;" );
}

static int GetFdFromSocket( JNIEnv *env, jobject obj )
{
	return GetFdFromObject( env, obj, "()Ljava/net/SocketImpl;" );
}

static int GetFdFromServerSocket( JNIEnv *env, jobject obj )
{
	/* Right now, the implementation is the same, though the class
	   is different. */
	return GetFdFromObject( env, obj, "()Ljava/net/SocketImpl;" );
}

static int GetFdFromUnknown( JNIEnv * env, jobject fd )
{
	int fd_val = -EINVAL;
	if ( env ) {
		if ( IsInstanceOf( env, fd, "java/io/FileDescriptor" ) )
			fd_val = GetFdFromFileDescriptor( env, fd );
		else if ( IsInstanceOf( env, fd, "java/net/DatagramSocket" ) )
			fd_val = GetFdFromDatagramSocket( env, fd );
		else if ( IsInstanceOf( env, fd, "java/net/Socket" ) )
			fd_val = GetFdFromSocket( env, fd );
		else if ( IsInstanceOf( env, fd, "java/net/ServerSocket" ) )
			fd_val = GetFdFromServerSocket( env, fd );
	}
	return fd_val;
}

/* ******************************************* */
/* Native Implementations of OnloadExt methods */
/* ******************************************* */

JNIEXPORT jboolean JNICALL
Java_OnloadExt_IsPresent ( JNIEnv *env, jclass cls )
{
	return (AreContstantsOk() && onload_is_present()) ? JNI_TRUE:JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_OnloadExt_SetStackName ( JNIEnv *env, jclass cls,
				jint who, jint scope, jstring stackname )
{
	jint rval;
	char* native_stackname = JNU_GetStringNativeChars(env, stackname);
	rval = onload_set_stackname( who, scope, native_stackname );
	free( (void*) native_stackname );
	return rval;
}

JNIEXPORT jint JNICALL
Java_OnloadExt_SetSpin(JNIEnv * env, jclass cls,
				jint spin_type, jboolean spin)
{
	int do_spin = spin == JNI_TRUE ? 1 : 0;
	return onload_thread_set_spin(spin_type, do_spin);
}

JNIEXPORT jint JNICALL
Java_OnloadExt_FdStat__ILOnloadExt_Stat_2 (JNIEnv * env, jclass cls,
						jint fd_val, jobject stat)
{
	jint rval;
	
	jclass stat_class;
	jfieldID field_sid;
	jfieldID field_name;
	jfieldID field_eid;
	jfieldID field_state;
	jstring stack_name;
	struct onload_stat native_stats;
	
	if ( !stat )
		return -EINVAL;
	
	stat_class = (*env)->GetObjectClass(env, stat);
	
	if ( !stat_class )
		return -EINVAL;
	
	field_sid   = (*env)->GetFieldID(env, stat_class, "stackId", "I");
	field_eid   = (*env)->GetFieldID(env, stat_class, "endpointId", "I");
	field_state = (*env)->GetFieldID(env, stat_class, "endpointState", "I");
	field_name  = (*env)->GetFieldID(env, stat_class, "stackName",
							"Ljava/lang/String;" );
	
	if ( !field_sid || !field_name || !field_eid || !field_state )
		return -EINVAL;

	(*env)->SetIntField( env, stat, field_sid, 0 );
	(*env)->SetIntField( env, stat, field_eid, 0 );
	(*env)->SetIntField( env, stat, field_state, 0 );
	stack_name = JNU_NewStringNative(env, "" );
	if ( stack_name )
		(*env)->SetObjectField( env, stat, field_name,
					stack_name );

        if ( fd_val < 0 )
            return -EINVAL;

	rval = onload_fd_stat( fd_val, &native_stats );

	if( rval ) { 
		(*env)->SetIntField( env, stat, field_sid,
					native_stats.stack_id );
		(*env)->SetIntField( env, stat, field_eid,
					native_stats.endpoint_id );
		(*env)->SetIntField( env, stat, field_state,
					native_stats.endpoint_state );
		if ( native_stats.stack_name ) {
			stack_name = JNU_NewStringNative(env,
					native_stats.stack_name );
			if ( stack_name )
				(*env)->SetObjectField( env, stat, field_name,
					stack_name );
		}
	}
	return rval;
}

JNIEXPORT jint JNICALL
Java_OnloadExt_FdStat (JNIEnv * env, jclass cls,
			jobject fd, jobject stat)
{
	jint fd_val = GetFdFromUnknown( env, fd );
	return Java_OnloadExt_FdStat__ILOnloadExt_Stat_2( env, cls,
							fd_val, stat );
}

JNIEXPORT jint JNICALL
Java_OnloadExt_CheckFeature (JNIEnv * env, jclass cls, jint fd, jint feature )
{
	return onload_fd_check_feature( fd, feature );
}

/* ******** */
/* Zerocopy */
/* ******** */

JNIEXPORT jboolean JNICALL
Java_OnloadZeroCopy_IsZeroCopyEnabled(JNIEnv* env, jclass cls)
{
	/* We need onload_ext to be present, and for DirectByteBuffer to work.
	  - DirectByteBuffer isnt supported by all VMs */
	jboolean rval = JNI_FALSE;
	if ( Java_OnloadExt_IsPresent( env, cls ) )
	{
		void* buffer = alloca(8);
		jobject test = (*env)->NewDirectByteBuffer(env, buffer, 2048);
		if ( test ) {
			if ( (*env)->GetDirectBufferAddress( env, test )
					== buffer )
				rval = JNI_TRUE;
			(*env)->DeleteLocalRef(env, test);
		}
	}
	return rval;
}

enum onload_zc_callback_rc
native_zerocopy_recv_callback(struct onload_zc_recv_args *args, int flags)
{
	struct native_zc_userdata* ptr;
	int i;
	JNIEnv* env;
	jobject cb;
	int fd;
	jclass cls;
	jmethodID mid;
	jobjectArray array;
	
	ptr = (struct native_zc_userdata*) args->user_ptr;
	env = ptr->env;
	cb = ptr->cb;
	fd = ptr->fd;
	
	/* TODO: Cache these? */
	cls = (*env)->GetObjectClass(env, cb);
	mid = (*env)->GetMethodID(env, cls, "RecvCallback",
					"([LOnloadZeroCopy;I)I");
	if ( !mid )
		return ONLOAD_ZC_TERMINATE;
	jclass Class_ZeroCopy = (*env)->FindClass(env,"LOnloadZeroCopy;");
	if ( !Class_ZeroCopy )
		return ONLOAD_ZC_TERMINATE;
	
	/* args->msg.msghdr.msg_iovlen is usually 1;
	   but we can't rely on that, so use an array. */
	array = (*env)->NewObjectArray(env, args->msg.msghdr.msg_iovlen,
						Class_ZeroCopy, NULL );
	if ( !array )
		return ONLOAD_ZC_TERMINATE;
	
	for ( i=0; i<args->msg.msghdr.msg_iovlen; ++i )
	{
		/* We're creating a fresh data bufer each time.
		   This means zc_recv is probably going to be slower than
		   normal recv right now. */
		jobject zc = NewZcBuffer( env, args->msg.iov+i, fd );
		if ( !zc || (*env)->ExceptionOccurred(env) )
			return ONLOAD_ZC_TERMINATE;
		
		(*env)->SetObjectArrayElement( env, array, i, zc );
	}
	return (*env)->CallIntMethod( env, cb, mid, array, flags );
}

JNIEXPORT jint JNICALL
Java_OnloadZeroCopy_Recv__LOnloadZeroCopy_Callback_2II(JNIEnv* env, jclass cls,
						jobject cb, jint flags, jint fd)
{
	struct onload_zc_recv_args args;
	memset( &args, 0, sizeof(args) );
	struct native_zc_userdata data;
	data.env = env;
	data.cb = cb;
	data.fd = fd;
	args.cb = native_zerocopy_recv_callback;
	args.user_ptr = &data;
	args.flags = flags & ONLOAD_ZC_RECV_FLAGS_MASK;
	
	return onload_zc_recv(fd, &args);
}

JNIEXPORT jint JNICALL
Java_OnloadZeroCopy_Recv(JNIEnv* env, jclass cls, jobject cb,
				jint flags, jobject fd)
{
	int native_fd = GetFdFromUnknown( env, fd );
	return Java_OnloadZeroCopy_Recv__LOnloadZeroCopy_Callback_2II(env, cls,
							cb, flags, native_fd );
}

JNIEXPORT jint JNICALL
Java_OnloadZeroCopy_Alloc__I_3Ljava_nio_ByteBuffer_2I(JNIEnv* env, jclass cls,
				jint flags, jobjectArray array, jint fd )
{
	struct onload_zc_iovec* iovecs;
	jsize i;
	jsize num = (*env)->GetArrayLength(env, array);
	int got;
	
	if ( num < 1 ) return -ENOMEM;
	
	iovecs = (struct onload_zc_iovec*) alloca(
			sizeof(struct onload_zc_iovec) * num );
	if ( !iovecs ) return -ENOMEM;
	
	got = onload_zc_alloc_buffers( fd, iovecs, num, flags );
	if ( got < 0 )
		return got;
	
	for( i=0; i<num; ++i ) {
		jobject buffer = NewZcBuffer( env, iovecs+i, fd );
		if ( !buffer || (*env)->ExceptionOccurred(env) ) return -ENOMEM;
		(*env)->SetObjectArrayElement( env, array, i, buffer );
	}
	return got;
}

JNIEXPORT jint JNICALL
Java_OnloadZeroCopy_Alloc(JNIEnv* env, jclass cls,
					jint flags, jobject array, jobject fd )
{
	int native_fd = GetFdFromUnknown( env, fd );
	return Java_OnloadZeroCopy_Alloc__I_3Ljava_nio_ByteBuffer_2I( env, cls,
						flags, array, native_fd );
}

JNIEXPORT jint JNICALL
Java_OnloadZeroCopy_Release__LOnloadZeroCopy_2(JNIEnv* env, jclass cls,
								jobject buffer)
{
	jint fd;
	onload_zc_handle handle;
	jlong opaque;

	opaque = GetLongFromObject( env, buffer, "opaque" );
	if ( (*env)->ExceptionOccurred(env) )
		return 0;
	fd = GetIntFromObject( env, buffer, "associated_fd" );
	if ( (*env)->ExceptionOccurred(env) )
		return 0;
	handle = (onload_zc_handle) opaque;
	return onload_zc_release_buffers( fd, &handle, 1 );
}

JNIEXPORT jint JNICALL
Java_OnloadZeroCopy_Release___3LOnloadZeroCopy_2(JNIEnv* env, jclass cls,
							jobjectArray buffers)
{
	jsize i;
	jsize num = (*env)->GetArrayLength(env, buffers);
	
	if ( (*env)->ExceptionOccurred(env) )
		return 0;
	if ( num < 1 )
		return -ENOMEM;

	for( i=0; i<num; ++i ) {
		jint rval = Java_OnloadZeroCopy_Release__LOnloadZeroCopy_2(
			env, cls,
			(*env)->GetObjectArrayElement( env, buffers, i ) );
		if ( rval < 0 )
			return rval;
		if ( (*env)->ExceptionOccurred(env) )
			return 0;
	}
	return num;
}

JNIEXPORT jint JNICALL
Java_OnloadZeroCopy_Send___3Ljava_nio_ByteBuffer_2II ( JNIEnv* env, jclass cls,
				jobjectArray array, jint flags, jint fd )
{
	jsize length, i;
	struct onload_zc_mmsg instruction;
	struct onload_zc_iovec* sendBuffer = NULL;
	int rval = -ENOMEM;
	
	length = (*env)->GetArrayLength(env, array);
	if ( (*env)->ExceptionOccurred(env) )
		return 0;

	sendBuffer = alloca( length * sizeof(struct onload_zc_iovec) );
	if ( !sendBuffer )
		return -ENOMEM;
	
	/* TODO: is this array length zero often enough to warrant a simpler
	   method here? */
	for ( i=0; i<length; ++i ) {
		void* data;
		jlong dataLength;
		jobject entry;
		jobject wrapper = (*env)->GetObjectArrayElement( env, array, i );
		if ( !wrapper )
			return -ENOMEM;
 		entry = GetObjectFromObject( env, wrapper, "buffer",
						"Ljava/nio/ByteBuffer;" );
		if ( !entry )
			return -ENOMEM;
		
		data = (*env)->GetDirectBufferAddress( env, entry );
		if ( !data )
			return -ENOMEM;
		dataLength = (*env)->GetDirectBufferCapacity( env, entry );
		if ( dataLength < 1 )
			return -ENOMEM;
		
		sendBuffer[i].iov_base = data;
		sendBuffer[i].iov_len = dataLength;
		sendBuffer[i].buf = (void*) GetLongFromObject( env, wrapper,
								"opaque" );
		sendBuffer[i].iov_flags = 0;
	}
	/* IMPORTANT - MUST ZERO OUT UNUSED MEMBERS */
	memset( &instruction, 0, sizeof( struct onload_zc_mmsg ) );
	/* And set what we actually want to send */
	instruction.msg.iov = sendBuffer;
	instruction.fd = fd;

	rval = onload_zc_send( &instruction, length, flags );
	if ( rval >= 0 )
		rval = instruction.rc;

	return rval;
}

JNIEXPORT jint JNICALL
Java_OnloadZeroCopy_Send ( JNIEnv* env, jclass cls,
				jobjectArray array, jint flags, jobject fd )
{
	int native_fd = GetFdFromUnknown( env, fd );
	return Java_OnloadZeroCopy_Send___3Ljava_nio_ByteBuffer_2II( env, cls,
						array, flags, native_fd );
}


/* ************** */
/* Templated Send */
/* ************** */

JNIEXPORT jboolean JNICALL
Java_OnloadTemplateSend_IsTemplatedSendEnabled (JNIEnv* env, jclass cls)
{
	/* Same requirements as zerocopy -
	   We need onload_ext to be present, and for DirectByteBuffer to work.
	  - DirectByteBuffer isnt supported by all VMs */
	/* TODO: We also really ought to check if we're on a 7122, but we have
	   no way to easily do so. */
	return Java_OnloadZeroCopy_IsZeroCopyEnabled(env, cls);
}

JNIEXPORT jint JNICALL
Java_OnloadTemplateSend_Alloc ( JNIEnv* env, jclass cls,
                                jint fd, jobject out, jobject data,
                                jint flags )
{
	jint rval = 0;
	onload_template_handle handle = 0;
	struct iovec initial_msg;

	initial_msg.iov_base = (*env)->GetDirectBufferAddress( env, data );
	if ( !initial_msg.iov_base )
		return -ENOMEM;
	initial_msg.iov_len = (*env)->GetDirectBufferCapacity( env, data );
	if ( initial_msg.iov_len < 1 )
		return -ENOMEM;

	rval = onload_msg_template_alloc(fd, &initial_msg, 1, &handle, flags );

	if ( rval >= 0 ) {
		SetLongOnObject( env, out, "opaque", (long)handle );
		SetIntOnObject( env, out, "fd", fd );
	} else {
		SetLongOnObject( env, out, "opaque", -1 );
		SetIntOnObject( env, out, "fd", -1 );
	}

	return rval;
}

JNIEXPORT jint JNICALL
Java_OnloadTemplateSend_Alloc__Ljava_net_ServerSocket_2LOnloadTemplateSend_2Ljava_nio_ByteBuffer_2
			(JNIEnv* env, jclass cls, jobject sock, jobject out,
			jobject data, jint flags )
{
	int fd = GetFdFromUnknown( env, sock );
	if ( (*env)->ExceptionOccurred(env) )
		return -EINVAL;
	return Java_OnloadTemplateSend_Alloc( env, cls, fd, out, data, flags );
}

JNIEXPORT jint JNICALL
Java_OnloadTemplateSend_Alloc__Ljava_net_Socket_2LOnloadTemplateSend_2Ljava_nio_ByteBuffer_2I
			(JNIEnv* env, jclass cls, jobject sock, jobject out,
			jobject data, jint flags )
{
	int fd = GetFdFromUnknown( env, sock );
	if ( (*env)->ExceptionOccurred(env) )
		return -EINVAL;
	return Java_OnloadTemplateSend_Alloc( env, cls, fd, out, data, flags );
}

JNIEXPORT jint JNICALL
Java_OnloadTemplateSend_Alloc__Ljava_io_FileDescriptor_2LOnloadTemplateSend_2Ljava_nio_ByteBuffer_2I
			(JNIEnv* env, jclass cls, jobject sock, jobject out,
			jobject data, jint flags )
{
	int fd = GetFdFromUnknown( env, sock );
	if ( (*env)->ExceptionOccurred(env) )
		return -EINVAL;
	return Java_OnloadTemplateSend_Alloc( env, cls, fd, out, data, flags );
}

JNIEXPORT jint JNICALL
Java_OnloadTemplateSend_Update ( JNIEnv* env, jclass cls,
                                 jobject handle, jobject data,
                                 jint offset, jint flags )
{
	jlong h = GetLongFromObject( env, handle, "handle" );
	struct onload_template_msg_update_iovec update;
	jint rval = 0;
	jint fd = GetIntFromObject( env, handle, "fd" );
	if ( (*env)->ExceptionOccurred(env) )
		return -EINVAL;

	update.otmu_base = (*env)->GetDirectBufferAddress( env, data );
	if ( !update.otmu_base )
		return -ENOMEM;
	update.otmu_len = (*env)->GetDirectBufferCapacity( env, data );
	if ( update.otmu_len < 1 )
		return -ENOMEM;

	update.otmu_offset = offset;
	update.otmu_flags = 0;

	rval = onload_msg_template_update( fd,
	                                   (onload_template_handle) h,
	                                   &update, 1, flags );
	if ( rval >= 0 && (flags & ONLOAD_TEMPLATE_FLAGS_SEND_NOW) ) {
		SetLongOnObject( env, handle, "opaque", -1 );
	}
	return rval;
}

JNIEXPORT jint JNICALL
Java_OnloadTemplateSend_Abort (JNIEnv* env, jclass cls,
                               jobject handle )
{
	jint rval = 0;
	jint fd;
	jlong h = GetLongFromObject( env, handle, "opaque" );
	if ( (*env)->ExceptionOccurred(env) )
		return -EINVAL;

	fd = GetIntFromObject( env, handle, "fd" );
	if ( (*env)->ExceptionOccurred(env) )
		return -EINVAL;

	rval = onload_msg_template_abort(fd, (onload_template_handle)h);

	if ( rval >= 0 ) {
		SetLongOnObject( env, handle, "opaque", -1 );
	}

	return rval;
}

