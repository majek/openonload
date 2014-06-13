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

/** JNI wrapper for the Onload extensions API.  Entirely static. */
public class OnloadExt {
    /** File-descriptor information. @see FdStat */
    public static class Stat {
      /** The stack number this fd is owned by. */
      public int stackId;
      /** The name of the stack (if any. */
      public String stackName;
      /** Unique identifier, usually matches the fd. */
      public int endpointId;
      /** Is the socket open, connected, listening etc.
       * @see /src/include/ci/internal/ip.h */
      public int endpointState;
      /** Default constructor */
      public Stat() {
          stackId = 0;
          stackName = "";
          endpointId = 0;
          endpointState = 0;
      }
    };

    /** Apply this name to just this thread.  @see SetStackName() */
    public static final int ONLOAD_THIS_THREAD       = 0;
    /** Apply this name to the whole process.  @see SetStackName() */
    public static final int ONLOAD_ALL_THREADS       = 1;

    /** Undo previous stackname change.  @see SetStackName() */
    public static final int ONLOAD_SCOPE_NOCHANGE    = 0;
    /** Make name local to each thread.  @see SetStackName() */
    public static final int ONLOAD_SCOPE_THREAD      = 1;
    /** Make name local to each process.  @see SetStackName() */
    public static final int ONLOAD_SCOPE_PROCESS     = 2;
    /** Make name local to each user.  @see SetStackName() */
    public static final int ONLOAD_SCOPE_USER        = 3;
    /** Make name global.  @see SetStackName() */
    public static final int ONLOAD_SCOPE_GLOBAL      = 4;
    
    /** Set all types of spin.  @see SetSpin */
    public static final int ONLOAD_SPIN_ALL          = 0;
    /** Alter spin for UDP receive only.  @see SetSpin */
    public static final int ONLOAD_SPIN_UDP_RECV     = 1;
    /** Alter spin for UDP send only.  @see SetSpin */
    public static final int ONLOAD_SPIN_UDP_SEND     = 2;
    /** Alter spin for TCP receive only.  @see SetSpin */
    public static final int ONLOAD_SPIN_TCP_RECV     = 3;
    /** Alter spin for TCP send only.  @see SetSpin */
    public static final int ONLOAD_SPIN_TCP_SEND     = 4;
    /** Alter spin for TCP accept only.  @see SetSpin */
    public static final int ONLOAD_SPIN_TCP_ACCEPT   = 5;
    /** Alter spin for pipe recevie only.  @see SetSpin */
    public static final int ONLOAD_SPIN_PIPE_RECV    = 6;
    /** Alter spin for pipe send only.  @see SetSpin */
    public static final int ONLOAD_SPIN_PIPE_SEND    = 7;
    /** Alter spin for select calls only.  @see SetSpin */
    public static final int ONLOAD_SPIN_SELECT       = 8;
    /** Alter spin for poll calls only.  @see SetSpin */
    public static final int ONLOAD_SPIN_POLL         = 9;
    /** Alter spin for TCP connect only.  @see SetSpin */
    public static final int ONLOAD_SPIN_PKT_WAIT     = 10;
    /** Alter spin for epoll only.  @see SetSpin */
    public static final int ONLOAD_SPIN_EPOLL_WAIT   = 11;
    /** Alter spin for when stack is already locked only.  @see SetSpin */
    public static final int ONLOAD_SPIN_STACK_LOCK   = 12;
    /** Alter spin for when socket is already locked only.  @see SetSpin */
    public static final int ONLOAD_SPIN_SOCK_LOCK    = 13;
    
    /** Check whether onload extensions are present.
     * @return True if running under onload. */
    public static native boolean IsPresent();
    /** Set the current stack name.
     * From this point onwards, until another call to this function overrides
     * it, sockets created by 'who' will be in 'stackname' (where the name is
     * local to 'scope')
     * @param who       should this call apply to only this thread, or the
     *                  whole process?  (Also used for 
     * @param scope     is the name system wide, or local to this thread etc.
     * @param stackname the stack to use
     * @return 0 on success, or a negative error code.
     * @see ONLOAD_THIS_THREAD
     * @see ONLOAD_ALL_THREADS
     * @see ONLOAD_SCOPE_NOCHANGE
     * @see ONLOAD_SCOPE_THREAD
     * @see ONLOAD_SCOPE_PROCESS
     * @see ONLOAD_SCOPE_USER
     * @see ONLOAD_SCOPE_GLOBAL
     */
    public static native int SetStackName (int who, int scope,
                                           String stackname );
    /** Set whether calls from this thread should spin or not.
     * Onload only cares about the underlying system call made, and will obey
     * any timeout specified, so spinning may be limited anyway.
     * @param spin_type the type of call to alter spin settings for.
     * @param spin      True to spin, False to disable spinning.
     * @see ONLOAD_SPIN_ALL
     * @see ONLOAD_SPIN_UDP_RECV
     * @see ONLOAD_SPIN_UDP_SEND
     * @see ONLOAD_SPIN_TCP_RECV
     * @see ONLOAD_SPIN_TCP_SEND
     * @see ONLOAD_SPIN_TCP_ACCEPT
     * @see ONLOAD_SPIN_PIPE_RECV
     * @see ONLOAD_SPIN_PIPE_SEND
     * @see ONLOAD_SPIN_SELECT
     * @see ONLOAD_SPIN_POLL
     * @see ONLOAD_SPIN_PKT_WAIT
     * @see ONLOAD_SPIN_EPOLL_WAIT
     * @see ONLOAD_SPIN_STACK_LOCK
     * @see ONLOAD_SPIN_SOCK_LOCK
     */
    public static native int SetSpin (int spin_type, boolean spin );
    /** Fill out onload statistics for a given socket
     * @param fd   the socket to get information on.
     * @param stat statistics structure, filled out by this call.
     * @return 0 on success, negative error code on failure.
     */
    public static native int FdStat (int fd, Stat stat );
    /** Fill out onload statistics for a given socket
     * This method relies on internal details and probably only works with
     * specific class libraries.  Use the fd version when possible -
     * it's faster anyway.
     * @param socket the socket to get information on.
     * @param stat   statistics structure, filled out by this call.
     * @return 0 on success, negative error code on failure.
     */
    public static native int FdStat (java.net.DatagramSocket socket, Stat stat );
    /** Fill out onload statistics for a given socket
     * This method relies on internal details and probably only works with
     * specific class libraries.  Use the fd version when possible -
     * it's faster anyway.
     * @param socket the socket to get information on.
     * @param stat   statistics structure, filled out by this call.
     * @return 0 on success, negative error code on failure.
     */
    public static native int FdStat (java.net.ServerSocket socket, Stat stat );
    /** Fill out onload statistics for a given socket
     * This method relies on internal details and probably only works with
     * specific class libraries.  Use the fd version when possible -
     * it's faster anyway.
     * @param socket the socket to get information on.
     * @param stat   statistics structure, filled out by this call.
     * @return 0 on success, negative error code on failure.
     */
    public static native int FdStat (java.net.Socket socket, Stat stat );
    /** Fill out onload statistics for a given socket
     * This method relies on internal details and probably only works with
     * specific class libraries.  Use the fd version when possible -
     * it's faster anyway.
     * @param socket the socket to get information on.
     * @param stat   statistics structure, filled out by this call.
     * @return 0 on success, negative error code on failure.
     */
    public static native int FdStat (java.io.FileDescriptor socket, Stat stat );
    
    /** Simple unit test and example */
    public static void main(String[] args) throws java.net.SocketException,
                                                  java.io.IOException
    {
      Stat stat = new Stat();
      if ( OnloadExt.IsPresent() ) {
        int rc;
        boolean ok = true;

        System.out.println( "Onload present." );
        System.out.println( "Testing.\n\n" );

        java.io.FileDescriptor d = new java.io.FileDescriptor();

        System.out.println( "Expected: oo:java[xxx]: Using OpenOnload xxx Copyright 2006-xxx Solarflare Communications, 2002-2005 Level 5 Networks [x]\n" );

        java.net.DatagramSocket s = new java.net.DatagramSocket( 5400 );

        rc = OnloadExt.SetStackName( ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, "Mary" );
        ok &= rc==0;
        rc = OnloadExt.SetSpin( ONLOAD_SPIN_ALL, true );
        java.net.ServerSocket s2 = new java.net.ServerSocket( 5401 );
        ok &= rc==0;

        System.out.println( "Expected: oo:java[xxx]: Using OpenOnload xxx Copyright 2006-xxx Solarflare Communications, 2002-2005 Level 5 Networks [y,Mary]" );

        java.net.Socket s3 = new java.net.Socket( "localhost", 5401 );

        rc = OnloadExt.FdStat( d, stat );
        System.out.println( "\n        Stack ID: " + stat.stackId
                  + " Name: " + stat.stackName
                  + " Endpoint ID: " + stat.endpointId
                  + " Endpoint State: " + stat.endpointState
                );
        System.out.println( "Expect: Stack ID: 0 Name:  Endpoint ID: nn Endpoint State: nn" );
        ok &= rc == 0;
        ok &= stat.stackId == 0;
        ok &= stat.stackName.equals("");
        ok &= stat.endpointState == 0;

        OnloadExt.FdStat( s, stat );
        System.out.println( "\n        Stack ID: " + stat.stackId
                  + " Name: " + stat.stackName
                  + " Endpoint ID: " + stat.endpointId
                  + " Endpoint State: " + stat.endpointState
                );
        System.out.println( "Expect: Stack ID: x Name:  Endpoint ID: nn Endpoint State: 45312" );
        ok &= rc == 0;
        ok &= stat.stackName.equals("");
        ok &= stat.endpointId > 0;
        ok &= stat.endpointState == 45312;

        OnloadExt.FdStat( s2, stat );
        System.out.println( "\n        Stack ID: " + stat.stackId
                  + " Name: " + stat.stackName
                  + " Endpoint ID: " + stat.endpointId
                  + " Endpoint State: " + stat.endpointState
                );
        System.out.println( "Expect: Stack ID: y Name: Mary Endpoint ID: nn Endpoint State: 4934" );
        ok &= rc == 0;
        ok &= stat.stackName.equals("Mary");
        ok &= stat.endpointId > 0;
        ok &= stat.endpointState == 4934;

        OnloadExt.FdStat( s3, stat );
        System.out.println( "\n        Stack ID: " + stat.stackId
                  + " Name: " + stat.stackName
                  + " Endpoint ID: " + stat.endpointId
                  + " Endpoint State: " + stat.endpointState
                );
        System.out.println( "Expect: Stack ID: y Name: Mary Endpoint ID: nn Endpoint State: 4934" );
        ok &= rc == 0;
        ok &= stat.stackName.equals("Mary");
        ok &= stat.endpointId > 0;
        ok &= stat.endpointState == 4934;

        s.close();
        s2.close();
        s3.close();

        if ( ok )
          System.out.println( "\n\t\tTest Passed" );
        else
          System.out.println( "\n\t\tTest FAILED" );

      } else {
        System.out.println( "Onload not present." );
      }
    }
    
    /** OnloadExt relies upon the OnloadExt C library */
    static{
      System.loadLibrary("OnloadExt");
    }
}
