/*
 * Copyright 1998-2009 University Corporation for Atmospheric Research/Unidata
 *
 * Portions of this software were developed by the Unidata Program at the
 * University Corporation for Atmospheric Research.
 *
 * Access and use of this software shall impose the following obligations
 * and understandings on the user. The user is granted the right, without
 * any fee or cost, to use, copy, modify, alter, enhance and distribute
 * this software, and any derivative works thereof, and its supporting
 * documentation for any purpose whatsoever, provided that this entire
 * notice appears in all copies of the software, derivative works and
 * supporting documentation.  Further, UCAR requests that the user credit
 * UCAR/Unidata in any publications that result from the use of this
 * software or in any product that includes this software. The names UCAR
 * and/or Unidata, however, may not be used in any advertising or publicity
 * to endorse or promote any products or commercial entity unless specific
 * written permission is obtained from UCAR/Unidata. The user also
 * understands that UCAR/Unidata is not obligated to provide the user with
 * any support, consulting, training or assistance of any kind with regard
 * to the use, operation and performance of this software nor to provide
 * the user with any updates, revisions, new versions or "bug fixes."
 *
 * THIS SOFTWARE IS PROVIDED BY UCAR/UNIDATA "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL UCAR/UNIDATA BE LIABLE FOR ANY SPECIAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE ACCESS, USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package ucar.httpservices;

import net.jcip.annotations.NotThreadSafe;
import org.apache.http.*;
import org.apache.http.auth.*;
import org.apache.http.client.CookieStore;
import org.apache.http.client.*;
import org.apache.http.client.CookieStore;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.DeflateDecompressingEntity;
import org.apache.http.client.entity.GzipDecompressingEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.params.AllClientPNames;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.*;
import org.apache.http.cookie.Cookie;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.*;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import java.io.*;
import java.net.*;
import java.nio.charset.UnsupportedCharsetException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

import static org.apache.http.auth.AuthScope.ANY_HOST;
import static org.apache.http.auth.AuthScope.ANY_PORT;
import static org.apache.http.auth.AuthScope.ANY_REALM;
import static ucar.httpservices.HTTPAuthScope.ANY_PRINCIPAL;

/**
 * A session is encapsulated in an instance of the class
 * HTTPSession.  The encapsulation is with respect to a specific url
 * This means that once a session is
 * specified, it is tied permanently to that url.
 * This class encapsulates an HTTP HttpSession object,
 * as well as encapsulates an instance of an Apache HttpClient.
 * <p/>
 * <p/>
 * It is possible to specify a url when invoking, for example,
 * HTTPFactory.Get.  This is because the url argument to the
 * HTTPSession constructor actually serves two purposes.  First, if
 * the method is created without specifying a url, then the session
 * url is used to specify the data to be retrieved by the method
 * invocation.  Second, if the method is created and specifies a
 * url, for example, HTTPMethod m = HTTPFactory.Get(session,url2);
 * this second url is used to specify the data to be retrieved by
 * the method invocation. In this situation, the url given to HTTPSession
 * should generally be the protocol+host+port.
 * <p/>
 * The important point is that in this second method, the url must
 * be "compatible" with the session url.  The term "compatible"
 * basically means that the HTTPSession url's host+port must be the same
 * as that of the url given to HTTPFactory.Get. This maintains the
 * semantics of the Session but allows flexibility in accessing data
 * from the server.
 * <p/>
 * Note that the term legalurl means that the url has reserved
 * characters within identifiers in escaped form. This is
 * particularly and issue for queries. Especially: ?x[0:5] is legal
 * and the square brackets need not be encoded.
 * <p/>
 * Finally, note that a session cannot be created without a realm (host+port).
 * <p/>
 * It is important to note that as the move to Apache Httpclient 4.3.x,
 * the HttpClient objects are generally immutable. This means that
 * at least this class (HTTPSession) and HTTPMethod must store
 * the relevant info and create the HttpClient and HttpMethod objects
 * dynamically. This also means that when a parameter is changed
 * (Agent, for example), any existing cached HttpClient must be thrown
 * away and reconstructed using the change. As a rule, the HttpClient
 * object will be created at the last minute so that multiple parameter
 * changes can be effected without have to re-create the HttpClient
 * for each parameter change.
 */

@NotThreadSafe
public class HTTPSession implements AutoCloseable
{
    //////////////////////////////////////////////////
    // Constants

    // Define all the legal properties
    // From class AllClientPNames
    // To do: AllClientPNames is deprecated
    // Use aliases because in Httpclient 4.3, AllClientPNames is deprecated

    static public final String ALLOW_CIRCULAR_REDIRECTS = AllClientPNames.ALLOW_CIRCULAR_REDIRECTS;
    static public final String HANDLE_REDIRECTS = AllClientPNames.HANDLE_REDIRECTS;
    static public final String HANDLE_AUTHENTICATION = AllClientPNames.HANDLE_AUTHENTICATION;
    static public final String MAX_REDIRECTS = AllClientPNames.MAX_REDIRECTS;
    static public final String SO_TIMEOUT = AllClientPNames.SO_TIMEOUT;
    static public final String CONN_TIMEOUT = AllClientPNames.CONNECTION_TIMEOUT;
    static public final String COOKIE_STORE = org.apache.http.client.protocol.HttpClientContext.COOKIE_STORE;

    static public final String USER_AGENT = AllClientPNames.USER_AGENT;
    static public final String PROXY = AllClientPNames.DEFAULT_PROXY;
    static public final String COMPRESSION = "COMPRESSION";
    static public final String CONN_REQ_TIMEOUT = "http.connection_request.timeout";

    static public final String RETRIES = "http.retries";
    static public final String UNAVAILRETRIES = "http.service_unavailable";

    // from: http://en.wikipedia.org/wiki/List_of_HTTP_header_fields
    static final public String HEADER_USERAGENT = "User-Agent";
    static final public String ACCEPT_ENCODING = "Accept-Encoding";

    static final public String BASIC = HTTPAuthPolicy.BASIC;
    static final public String DIGEST = HTTPAuthPolicy.DIGEST;
    static final public String NTLM = HTTPAuthPolicy.NTLM;
    static final public String SSL = HTTPAuthPolicy.SSL;

    static final int DFALTTHREADCOUNT = 50;
    static final int DFALTREDIRECTS = 25;

    static final String DFALTUSERAGENT = "/NetcdfJava/HttpClient4.3";

    static final int DFALTCONNTIMEOUT = 1 * 60 * 1000; // 1 minutes (60000 milliseconds)
    static final int DFALTCONNREQTIMEOUT = DFALTCONNTIMEOUT;
    static final int DFALTSOTIMEOUT = 5 * 60 * 1000; // 5 minutes (300000 milliseconds)

    static final int DFALTRETRIES = 3;
    static final int DFALTUNAVAILRETRIES = 3;
    static final int DFALTUNAVAILINTERVAL = 3000; // 3 seconds

    //////////////////////////////////////////////////////////////////////////
    // Type Declarations

    /**
     * Sub-class List<String,Object> for mnemonic convenience.
     */
    static class Settings extends HashMap<String, Object>
    {
        public Settings()
        {
        }

        public Set<String>
        getNames()
        {
            return super.keySet();
        }

        public Set<String>
        getKeys()
        {
            return keySet();
        }

        public Object getParameter(String param)
        {
            return super.get(param);
        }

        public void setParameter(String param, Object value)
        {
            super.put(param, value);
        }

        public Object removeParameter(String param)
        {
            return super.remove(param);
        }
    }

    static class Proxy
    {
        public String host = null;
        public int port = -1;
        public String userpwd = null;
    }

    static enum Methods
    {
        Get("get"), Head("head"), Put("put"), Post("post"), Options("options");
        private final String name;

        Methods(String name)
        {
            this.name = name;
        }

        public String getName()
        {
            return name;
        }
    }

    // Define a Retry Handler that supports specifiable retries
    // and is optionally verbose.
    /* TBD for 4.3.x  */
    static public class RetryHandler
        implements org.apache.http.client.HttpRequestRetryHandler
    {
        static final int DFALTRETRIES = 5;
        static int retries = DFALTRETRIES;
        static boolean verbose = false;

        public RetryHandler()
        {
        }

        public boolean
        retryRequest(IOException exception,
                     int executionCount,
                     HttpContext context)
        {
            if(getVerbose()) {
                HTTPSession.log.debug(String.format("Retry: count=%d exception=%s", executionCount, exception.toString()));
            }
            synchronized (RetryHandler.class) {
                if(executionCount >= retries)
                    return false;
            }
            if((exception instanceof InterruptedIOException) // Timeout
                || (exception instanceof UnknownHostException)
                || (exception instanceof ConnectException) // connection refused
                || (exception instanceof SSLException)) // ssl handshake problem
                return false;
            HttpRequest request
                = (HttpRequest) context.getAttribute(ExecutionContext.HTTP_REQUEST);
            boolean idempotent = !(request instanceof HttpEntityEnclosingRequest);
            if(idempotent) // Retry if the request is considered idempotent
                return true;

            return false;
        }

        static public synchronized int getRetries()
        {
            return RetryHandler.retries;
        }

        static public synchronized void setRetries(int retries)
        {
            if(retries > 0)
                RetryHandler.retries = retries;
        }

        static public synchronized boolean getVerbose()
        {
            return RetryHandler.verbose;
        }

        static public synchronized void setVerbose(boolean tf)
        {
            RetryHandler.verbose = tf;
        }
    }


    static class GZIPResponseInterceptor implements HttpResponseInterceptor
    {
        public void process(final HttpResponse response, final HttpContext context)
            throws HttpException, IOException
        {
            HttpEntity entity = response.getEntity();
            if(entity != null) {
                Header ceheader = entity.getContentEncoding();
                if(ceheader != null) {
                    HeaderElement[] codecs = ceheader.getElements();
                    for(HeaderElement h : codecs) {
                        if(h.getName().equalsIgnoreCase("gzip")) {
                            response.setEntity(new GzipDecompressingEntity(response.getEntity()));
                            return;
                        }
                    }
                }
            }
        }
    }


    static class DeflateResponseInterceptor implements HttpResponseInterceptor
    {
        public void process(final HttpResponse response, final HttpContext context)
            throws HttpException, IOException
        {
            HttpEntity entity = response.getEntity();
            if(entity != null) {
                Header ceheader = entity.getContentEncoding();
                if(ceheader != null) {
                    HeaderElement[] codecs = ceheader.getElements();
                    for(HeaderElement h : codecs) {
                        if(h.getName().equalsIgnoreCase("deflate")) {
                            response.setEntity(new DeflateDecompressingEntity(response.getEntity()));
                            return;
                        }
                    }
                }
            }
        }
    }


    ////////////////////////////////////////////////////////////////////////
    // Static variables

    static public org.slf4j.Logger log
        = org.slf4j.LoggerFactory.getLogger(HTTPSession.class);

    // Use simple map to hold all the
    // settable values; there will be one
    // instance for global and one for local.

    static protected Settings globalsettings;

    // As taken from the command line, usually
    static protected KeyStore keystore = null;
    static protected KeyStore truststore = null;
    static protected String keypassword = null;
    static protected String trustpassword = null;

    static protected Boolean globaldebugheaders = null;

    // Shared by all sessions
    static protected PoolingHttpClientConnectionManager connmgr;

    // This is a hack to suppress content-encoding headers from request
    static protected HttpResponseInterceptor CEKILL;
    // Debug Header interceptors
    static protected List<HttpRequestInterceptor> dbgreq = new ArrayList<>();
    static protected List<HttpResponseInterceptor> dbgrsp = new ArrayList<>();

    static {
        CEKILL = new HTTPUtil.ContentEncodingInterceptor();

        // re: http://stackoverflow.com/a/19950935/444687
        // and http://stackoverflow.com/a/20491564/444687
        SSLContextBuilder builder = SSLContexts.custom();
        try {
            builder.loadTrustMaterial(null, new CustomTrustStrategy());
            SSLContext sslContext = builder.build();
            X509HostnameVerifier hv509 = new CustomX509HostNameVerifier();
            SSLConnectionSocketFactory sslsf = new CustomSSLSocketFactory(sslContext, hv509);
            Registry<ConnectionSocketFactory> r =
                RegistryBuilder.<ConnectionSocketFactory>create()
                    .register("https", sslsf)
                    .register("http", new PlainConnectionSocketFactory())
                    .build();
            connmgr = new PoolingHttpClientConnectionManager(r);
        } catch (NoSuchAlgorithmException nsae) {
            System.err.println("Authentication exception: " + nsae);
        } catch (KeyStoreException kse) {
            System.err.println("Authentication exception: " + kse);
        } catch (KeyManagementException kme) {
            System.err.println("Authentication exception: " + kme);
        }

        globalsettings = new Settings();
        globalsettings.setParameter(ALLOW_CIRCULAR_REDIRECTS, Boolean.TRUE);
        globalsettings.setParameter(MAX_REDIRECTS, (Integer) DFALTREDIRECTS);
        globalsettings.setParameter(SO_TIMEOUT, (Integer) DFALTSOTIMEOUT);
        globalsettings.setParameter(CONN_TIMEOUT, (Integer) DFALTCONNTIMEOUT);
        globalsettings.setParameter(CONN_REQ_TIMEOUT, (Integer) DFALTCONNREQTIMEOUT);
        globalsettings.setParameter(USER_AGENT, DFALTUSERAGENT);
        setGlobalThreadCount(DFALTTHREADCOUNT);
        setGlobalProxyFromD(); // get info from -D if possible
        setGlobalKeyStoreFromD(); // get info from -D if possible
    }

    //////////////////////////////////////////////////////////////////////////
    // Static Methods (Mostly global accessors)

    // Access defined global property
    static synchronized Object setGlobalParameter(String name, Object value)
    {
        if(name == null || name.length() == 0)
            throw new IllegalArgumentException();
        Object prev = globalsettings.getParameter(name);
        globalsettings.setParameter(name, value);
        return prev;
    }

    static synchronized Object getGlobalParameter(String name)
    {
        if(name == null || name.length() == 0)
            throw new IllegalArgumentException();
        return globalsettings.getParameter(name);
    }

    static synchronized public Settings getGlobalSettings()
    {
        return globalsettings;
    }

    static synchronized public void setGlobalThreadCount(int nthreads)
    {
        if(nthreads <= 0)
            throw new IllegalArgumentException();
        connmgr.setMaxTotal(nthreads);
        connmgr.setDefaultMaxPerRoute(nthreads);
    }

    // Alias
    static public void setGlobalMaxConnections(int nthreads)
    {
        setGlobalThreadCount(nthreads);
    }

    static synchronized public int getGlobalThreadCount()
    {
        return connmgr.getMaxTotal();
    }

    static public void setGlobalUserAgent(String useragent)
    {
        if(useragent == null || useragent.length() == 0)
            throw new IllegalArgumentException();
        setGlobalParameter(USER_AGENT, useragent);
    }

    static public String getGlobalUserAgent()
    {
        return (String) getGlobalParameter(USER_AGENT);
    }

    static public List<Cookie> getGlobalCookies()
    {
        CookieStore store = (CookieStore) getGlobalParameter(COOKIE_STORE);
        if(store == null) return null;
        return store.getCookies();
    }

    static public void setGlobalCookieStore(CookieStore store)
    {
        setGlobalParameter(COOKIE_STORE, store);
    }

    // Timeouts

    static public void setGlobalConnectionTimeout(int timeout)
    {
        if(timeout <= 0)
            throw new IllegalArgumentException();
        setGlobalParameter(CONN_TIMEOUT, (Integer) timeout);
        setGlobalParameter(CONN_REQ_TIMEOUT, (Integer) timeout);
    }

    static public void setGlobalSoTimeout(int timeout)
    {
        if(timeout <= 0)
            throw new IllegalArgumentException();
        setGlobalParameter(SO_TIMEOUT, (Integer) timeout);
    }

    // Proxy

    static synchronized public void
    setGlobalProxy(String host, int port, String userpwd)
    {
        if(host == null || host.length() == 0)
            throw new IllegalArgumentException();
        if(userpwd != null && userpwd.length() == 0)
            userpwd = null;
        if(userpwd != null && userpwd.indexOf(':') < 0)
            throw new IllegalArgumentException();
        Proxy proxy = new Proxy();
        proxy.host = host;
        proxy.port = port;
        proxy.userpwd = userpwd; // null if not authenticating
        setGlobalParameter(PROXY, proxy);
    }

    // Authorization

    static synchronized protected void
    defineCredentialsProvider(String principal, AuthScope scope, CredentialsProvider provider, HTTPAuthStore store)
    {
        if(store == null || scope == null)
            throw new IllegalArgumentException();
        if(principal == null || principal.length() == 0)
            principal = HTTPAuthStore.ANY_PRINCIPAL;
        // Add/remove entry to AuthStore
        try {
            if(provider == null) {//remove
                store.remove(new HTTPAuthStore.Entry(principal, scope, provider));
            } else { // add
                store.insert(new HTTPAuthStore.Entry(principal, scope, provider));
            }
        } catch (HTTPException he) {
            log.error("HTTPSession.setCredentialsProvider failed");
        }
    }

    static public void
    setGlobalCredentialsProvider(AuthScope scope, CredentialsProvider provider)
    {
        defineCredentialsProvider(ANY_PRINCIPAL, scope, provider, HTTPAuthStore.getDefault());
    }

    static public void
    setGlobalCredentialsProvider(CredentialsProvider provider)
    {
        defineCredentialsProvider(ANY_PRINCIPAL, HTTPAuthScope.ANY, provider, HTTPAuthStore.getDefault());
    }

    // It is convenient to be able to directly set the Credentials
    // (not the provider) when those credentials are fixed.
    static public void
    setGlobalCredentials(AuthScope scope, Credentials creds)
    {
        CredentialsProvider provider = new HTTPConstantProvider(creds);
        setGlobalCredentialsProvider(scope, provider);
    }

    /* TBD for 4.3.x
    static public int
    getRetryCount()
    {
        return RetryHandler.getRetries();
    }

    static public void
    setRetryCount(int count)
    {
        RetryHandler.setRetries(count);
    }
    */


    //////////////////////////////////////////////////
    // Static Utility functions

    static public String
    getUrlAsString(String url) throws HTTPException
    {
        try (
            HTTPMethod m = HTTPFactory.Get(url);) {
            int status = m.execute();
            String content = null;
            if(status == 200) {
                content = m.getResponseAsString();
            }
            return content;
        }
    }

    static public int
    putUrlAsString(String content, String url) throws HTTPException
    {
        int status = 0;
        try {
            try (HTTPMethod m = HTTPFactory.Put(url)) {
                m.setRequestContent(new StringEntity(content,
                    ContentType.create("application/text", "UTF-8")));
                status = m.execute();
            }
        } catch (UnsupportedCharsetException uce) {
            throw new HTTPException(uce);
        }
        return status;
    }

    static protected String
    getstorepath(String prefix)
    {
        String path = System.getProperty(prefix + "store");
        if(path != null) {
            path = path.trim();
            if(path.length() == 0) path = null;
        }
        return path;
    }

    static protected String
    getpassword(String prefix)
    {
        String password = System.getProperty(prefix + "storepassword");
        if(password != null) {
            password = password.trim();
            if(password.length() == 0) password = null;
        }
        return password;
    }

    static protected String
    cleanproperty(String property)
    {
        String value = System.getProperty(property);
        if(value != null) {
            value = value.trim();
            if(value.length() == 0) value = null;
        }
        return value;
    }

    // For backward compatibility, provide
    // programmatic access for setting proxy info
    // Extract proxy info from command line -D parameters
    // extended 5/7/2012 to get NTLM domain
    // H/T: nick.bower@metoceanengineers.com
    static protected void
    setGlobalProxyFromD()
    {
        String host = System.getProperty("http.proxyHost");
        String port = System.getProperty("http.proxyPort");
        String userpwd = System.getProperty("http.proxyAuth");// in url form user:pwd
        int portno = -1;

        if(host != null) {
            host = host.trim();
            if(host.length() == 0) host = null;
        }
        if(port != null) {
            port = port.trim();
            if(port.length() > 0) {
                try {
                    portno = Integer.parseInt(port);
                } catch (NumberFormatException nfe) {
                    portno = -1;
                }
            }
        }
        Credentials creds = null;
        if(userpwd != null) {
            userpwd = userpwd.trim();
            if(userpwd.length() > 0 && userpwd.indexOf(':') > 0) {
                if(host != null)
                    setGlobalProxy(host, portno, userpwd);
            }
        }
    }

    static synchronized public void
    setGlobalDebugHeaders(boolean print)
    {
        globaldebugheaders = new Boolean(print);
    }

    static synchronized public void
    resetGlobalDebugHeaders()
    {
        globaldebugheaders = null;
    }

    //////////////////////////////////////////////////
    // Instance variables

    // Currently, the granularity of authorization is host+port.
    protected URL realmURL = null;
    protected String realmProtocol = null;
    protected String realmHost = null;
    protected int realmPort = -1;
    protected boolean closed = false;

    // Per-session counterpart of globalsettings
    protected Settings localsettings = new Settings();

    // The authstore to use
    protected HTTPAuthStore authlocal = HTTPAuthStore.getDefault();

    // Track method objects using this session: for closing.
    protected List<ucar.httpservices.HTTPMethod> methodlist = new Vector<HTTPMethod>();

    // We currently only allow the use of per-session interceptors
//    protected List<Object> intercepts = new ArrayList<Object>(); // current set of interceptors;

    // We currently only allow the use of HTTPSession instance interceptors
    // except for header debug
    protected List<HttpRequestInterceptor> reqintercepts = new ArrayList<HttpRequestInterceptor>();
    protected List<HttpResponseInterceptor> rspintercepts = new ArrayList<HttpResponseInterceptor>();

    // This context is re-used over all method executions 
    protected HttpClientContext execcontext = HttpClientContext.create();

    // cached and recreated as needed
    protected boolean cachevalid = false; // Are cached items up-to-date?
    protected CloseableHttpClient cachedclient = null;
    protected AuthScope cachedscope = null;
    protected URL cachedURL = null;

    // this is a security hole; not currently used
    protected String sessionid = null;

    //////////////////////////////////////////////////
    // Constructor(s)

    public HTTPSession()
        throws HTTPException
    {
        this(null);
    }

    public HTTPSession(String url)
        throws HTTPException
    {
        try {
            URL u = new URL(url);
            this.realmHost = u.getHost();
            this.realmPort = u.getPort();
            this.realmProtocol = u.getProtocol();
            u = new URL(this.realmProtocol, this.realmHost, this.realmPort, null);
            this.realmURL = u;
        } catch (MalformedURLException mue) {
            throw new HTTPException("Malformed URL: " + url, mue);
        }
        this.cachevalid = false; // Force build on first use
    }

    //////////////////////////////////////////////////
    // Interceptors

    public void
    setAllowCompression()
    {
        if(localsettings.getParameter(COMPRESSION) != null)
            removeCompression();
        localsettings.setParameter(COMPRESSION, "gzip,deflate");
        HttpResponseInterceptor hrsi = new GZIPResponseInterceptor();
        rspintercepts.add(hrsi);
        hrsi = new DeflateResponseInterceptor();
        rspintercepts.add(hrsi);
    }

    public void
    removeCompression()
    {
        if(localsettings.removeParameter(COMPRESSION) != null) {
            for(int i = rspintercepts.size() - 1;i >= 0;i--) { // walk backwards
                HttpResponseInterceptor hrsi = rspintercepts.get(i);
                if(hrsi instanceof GZIPResponseInterceptor
                    || hrsi instanceof DeflateResponseInterceptor)
                    rspintercepts.remove(i);
            }
        }
    }

    protected void
    setInterceptors(HttpClientBuilder cb)
    {
        for(HttpRequestInterceptor hrq : reqintercepts)
            cb.addInterceptorLast(hrq);
        for(HttpResponseInterceptor hrs : rspintercepts)
            cb.addInterceptorLast(hrs);
        // Add debug interceptors
        for(HttpRequestInterceptor hrq : dbgreq)
            cb.addInterceptorFirst(hrq);
        for(HttpResponseInterceptor hrs : dbgrsp)
            cb.addInterceptorFirst(hrs);
        // Hack: add Content-Encoding suppressor
        cb.addInterceptorFirst(CEKILL);
    }

    //////////////////////////////////////////////////
    // Per-session Accessor(s)

    HttpClient
    getClient()
    {
        return this.cachedclient;
    }

    public HTTPAuthStore
    getAuthStore()
    {
        return this.authlocal;
    }

    public void
    setAuthStore(HTTPAuthStore store)
    {
        if(store == null) store = HTTPAuthStore.getDefault();
        this.authlocal = store;
    }

    public Settings getSettings()
    {
        return localsettings;
    }

    public URL getURL()
    {
        return this.realmURL;
    }

    public void setUserAgent(String agent)
    {
        if(agent == null || agent.length() == 0)
            throw new IllegalArgumentException();
        localsettings.setParameter(USER_AGENT, agent);
        this.cachevalid = false;
    }

    public void setSoTimeout(int timeout)
    {
        if(timeout <= 0)
            throw new IllegalArgumentException();
        localsettings.setParameter(SO_TIMEOUT, timeout);
        this.cachevalid = false;
    }

    public void setConnectionTimeout(int timeout)
    {
        if(timeout <= 0)
            throw new IllegalArgumentException();
        localsettings.setParameter(CONN_TIMEOUT, timeout);
        localsettings.setParameter(CONN_REQ_TIMEOUT, timeout);
        this.cachevalid = false;
    }

    public void setMaxRedirects(int n)
    {
        if(n < 0) //validate
            throw new IllegalArgumentException();
        localsettings.setParameter(MAX_REDIRECTS, n);
        this.cachevalid = false;
    }

    //////////////////////////////////////////////////

    /**
     * Close the session. This implies closing
     * any open methods.
     */

    synchronized public void close()
    {
        if(this.closed)
            return;
        this.closed = true;
        List<HTTPMethod> ml = this.methodlist;
        this.methodlist = null;
        while(ml.size() > 0) {
            HTTPMethod m = ml.get(0);
            m.close(); // forcibly close; will invoke removemethod()
        }
    }

    synchronized void removeMethod(HTTPMethod m)
    {
        if(this.closed)
            return;
        if(methodlist != null)
            methodlist.remove(m);
    }

    synchronized void addMethod(HTTPMethod m)
    {
        if(this.closed)
            throw new IllegalStateException("Session is closed");
        if(methodlist != null && !methodlist.contains(m))
            methodlist.add(m);
    }

    public void clearState()
    {
        this.localsettings.clear();
        this.authlocal.clear();
    }

    //////////////////////////////////////////////////
    // Possibly authenticating proxy

    // All proxy activity goes thru here
    void
    setProxy(Proxy proxy)
    {
        if(proxy != null && proxy.host != null)
            localsettings.setParameter(PROXY, proxy);
        this.cachevalid = false;
    }

    //////////////////////////////////////////////////
    // External API

    public void
    setProxy(String host, int port, String userpwd /*user:pwd*/)
    {
        Proxy proxy = new Proxy();
        proxy.host = host;
        proxy.port = port;
        proxy.userpwd = userpwd;
        setProxy(proxy);
    }

    //////////////////////////////////////////////////
    // Authorization
    // per-session versions of the global accessors

    public void
    setCredentialsProvider(AuthScope scope, CredentialsProvider provider)
    {
        defineCredentialsProvider(ANY_PRINCIPAL, scope, provider, this.authlocal);
    }

    public void
    setCredentialsProvider(CredentialsProvider provider)
    {
        setCredentialsProvider(HTTPAuthScope.ANY, provider);
    }

    public void
    setCredentialsProvider(String scheme, CredentialsProvider provider)
    {
        AuthScope scope = new AuthScope(ANY_HOST, ANY_PORT, ANY_REALM, scheme);
        setCredentialsProvider(scope, provider);
    }

    public void
    setCredentials(String scheme, Credentials creds)
    {
        CredentialsProvider provider = new HTTPConstantProvider(creds);
        setCredentialsProvider(scheme, provider);
    }

    // Assumes that user info exists in the url and we can
    // use it to build a simple UsernamePasswordCredentials as our provider.
    // Also assume this is a compatible url to the Session url
    public void
    setCredentialsProvider(String surl)
        throws HTTPException
    {
        // Try to extract user info
        URI uri = HTTPAuthScope.decompose(surl);
        String userinfo = uri.getUserInfo();
        if(userinfo != null) {
            int index = userinfo.indexOf(':');
            String user = userinfo.substring(index);
            String pwd = userinfo.substring(index + 1, userinfo.length());
            if(user != null && pwd != null) {
                // Create a non-interactive user+pwd handler
                CredentialsProvider bp = new HTTPBasicProvider(user, pwd);
                setCredentialsProvider(HTTPAuthPolicy.BASIC, bp);
            }
        }
    }

    //////////////////////////////////////////////////
    // Execution Support

    // Package visible

    /**
     * Called primarily from HTTPMethod to do the bulk
     * of the execution. Assumes HTTPMethod
     * has inserted its headers into request.
     *
     * @param request the execution request
     */

    HttpClientContext
    execute(HttpRequestBase request)
        throws HTTPException
    {
        try {
            this.cachedURL = request.getURI().toURL();
        } catch (MalformedURLException mue) {
            throw new HTTPException(mue);
        }
        RequestConfig.Builder rb = RequestConfig.custom();
        HttpHost target = httpHostFor(this.cachedURL);

        synchronized (this) {// keep coverity happy
            //Merge Settings;
            Settings merged = merge(globalsettings, localsettings);
            configureRequest(request, rb, merged);
            if(!this.cachevalid) {
                HttpClientBuilder cb = HttpClients.custom();
                configClient(cb, merged);
                setAuthentication(cb, rb, merged);
                this.cachedclient = cb.build();
            }
        }
        request.setConfig(rb.build());
        CloseableHttpResponse response;
        try {
            response = cachedclient.execute(target, request, this.execcontext);
        } catch (IOException ioe) {
            throw new HTTPException(ioe);
        }
        int code = response.getStatusLine().getStatusCode();
        // On authorization error, clear entries from the credentials cache
        if((code == HttpStatus.SC_UNAUTHORIZED)
            || (code == HttpStatus.SC_PROXY_AUTHENTICATION_REQUIRED)) {
            HTTPCachingProvider.invalidate(this.cachedscope);
        }
        return this.execcontext;
    }

/*
    ssl.TrustManagerFactory.algorithm
    javax.net.ssl.trustStoreType
    javax.net.ssl.trustStore
    javax.net.ssl.trustStoreProvider
    javax.net.ssl.trustStorePassword
    ssl.KeyManagerFactory.algorithm
    javax.net.ssl.keyStoreType
    javax.net.ssl.keyStore
    javax.net.ssl.keyStoreProvider
    javax.net.ssl.keyStorePassword
    https.protocols
    https.cipherSuites
    http.proxyHost
    http.proxyPort
    http.nonProxyHosts
    http.keepAlive
    http.maxConnections
    http.agent
*/

    protected void
    configureRequest(HttpRequestBase request, RequestConfig.Builder rb, Settings settings)
        throws HTTPException
    {
        // Always define these
        rb.setExpectContinueEnabled(true);
        rb.setAuthenticationEnabled(true);

        // Configure the RequestConfig
        for(String key: settings.getKeys()) {
            Object value = settings.getParameter(key);
            boolean tf = (value instanceof Boolean ? (Boolean) value : false);
            if(key.equals(ALLOW_CIRCULAR_REDIRECTS)) {
                rb.setCircularRedirectsAllowed(tf);
            } else if(key.equals(HANDLE_REDIRECTS)) {
                rb.setRedirectsEnabled(tf);
                rb.setRelativeRedirectsAllowed(tf);
            } else if(key.equals(MAX_REDIRECTS)) {
                rb.setMaxRedirects((Integer) value);
            } else if(key.equals(SO_TIMEOUT)) {
                rb.setSocketTimeout((Integer) value);
            } else if(key.equals(CONN_TIMEOUT)) {
                rb.setConnectTimeout((Integer) value);
            } else if(key.equals(CONN_REQ_TIMEOUT)) {
                rb.setConnectionRequestTimeout((Integer) value);
            } /* else ignore */
        }

        // Configure the request directly
        for(String key: settings.getKeys()) {
            Object value = settings.getParameter(key);
            boolean tf = (value instanceof Boolean ? (Boolean) value : false);
            if(key.equals(USER_AGENT)) {
                request.setHeader(HEADER_USERAGENT, value.toString());
            } else if(key.equals(COMPRESSION)) {
                request.setHeader(ACCEPT_ENCODING, value.toString());
            } // else ignore
        }
    }

    protected HttpHost
    httpHostFor(URL url)
    {
        return new HttpHost(url.getHost(), url.getPort(), url.getProtocol());
    }

    //////////////////////////////////////////////////
    // Testing support

    // Expose the state for testing purposes
    synchronized public boolean isClosed()
    {
        return this.closed;
    }

    synchronized public int getMethodcount()
    {
        return methodlist.size();
    }

    protected String getSessionID()
    {
        String sid = null;
        String jsid = null;
        List<Cookie> cookies = execcontext.getCookieStore().getCookies();
        for(Cookie cookie : cookies) {
            if(cookie.getName().equalsIgnoreCase("sessionid"))
                sid = cookie.getValue();
            if(cookie.getName().equalsIgnoreCase("jsessionid"))
                jsid = cookie.getValue();
        }
        return (sid == null ? jsid : sid);
    }

    //////////////////////////////////////////////////
    // COnfiguration

/*
    ssl.TrustManagerFactory.algorithm
    javax.net.ssl.trustStoreType
    javax.net.ssl.trustStore
    javax.net.ssl.trustStoreProvider
    javax.net.ssl.trustStorePassword
    ssl.KeyManagerFactory.algorithm
    javax.net.ssl.keyStoreType
    javax.net.ssl.keyStore
    javax.net.ssl.keyStoreProvider
    javax.net.ssl.keyStorePassword
    https.protocols
    https.cipherSuites
    http.proxyHost
    http.proxyPort
    http.nonProxyHosts
    http.keepAlive
    http.maxConnections
    http.agent
*/

    protected void
    configClient(HttpClientBuilder cb, Settings settings)
        throws HTTPException
    {
        // Set retries
        cb.setRetryHandler(new DefaultHttpRequestRetryHandler(DFALTRETRIES, false));
        cb.setServiceUnavailableRetryStrategy(new DefaultServiceUnavailableRetryStrategy(DFALTUNAVAILRETRIES, DFALTUNAVAILINTERVAL));
        setInterceptors(cb);
    }


    /**
     * Handle authentication.
     * We do not know, necessarily,
     * which scheme(s) will be
     * encountered, so most testing
     * occurs in HTTPAuthProvider
     *
     * @return an authprovider encapsulting the request
     */

    synchronized protected void
    setAuthentication(HttpClientBuilder cb, RequestConfig.Builder rb, Settings settings)
        throws HTTPException
    {
        // Creat a authscope from the url
        String[] principalp = new String[1];
        if(this.cachedURL == null)
            this.cachedscope = HTTPAuthScope.ANY;
        else
            this.cachedscope = HTTPAuthScope.urlToScope(HTTPAuthPolicy.BASIC, this.cachedURL);

        // Provide a credentials (provider) to enact the process
        // We use the a caching instance so we can intercept getCredentials
        // requests to check the cache.
        // Changes in httpclient 4.3 may make this simpler, but for now, leave alone

        HTTPCachingProvider hap = new HTTPCachingProvider(this.getAuthStore(), this.cachedscope, principalp[0]);
        cb.setDefaultCredentialsProvider(hap);

        // Handle proxy, including proxy auth.
        Object value = settings.getParameter(PROXY);
        if(value != null) {
            Proxy proxy = (Proxy) value;
            if(proxy.host != null) {
                HttpHost httpproxy = new HttpHost(proxy.host, proxy.port);
                // Not clear which is the correct approach
                if(false) {
                    DefaultProxyRoutePlanner routePlanner = new DefaultProxyRoutePlanner(httpproxy);
                    cb.setRoutePlanner(routePlanner);
                } else {
                    rb.setProxy(httpproxy);
                }
                // Add any proxy credentials
                if(proxy.userpwd != null) {
                    AuthScope scope = new AuthScope(httpproxy);
                    hap.setCredentials(scope, new UsernamePasswordCredentials(proxy.userpwd));
                }

            }
        }

        try {
            if(truststore != null || keystore != null) {
                SSLContextBuilder builder = SSLContexts.custom();
                if(truststore != null) {
                    builder.loadTrustMaterial(truststore,
                        new TrustSelfSignedStrategy());
                }
                if(keystore != null) {
                    builder.loadKeyMaterial(keystore, keypassword.toCharArray());
                }
                SSLContext sslcxt = builder.build();
                SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcxt);

                cb.setSSLSocketFactory(sslsf);

            }
        } catch (KeyStoreException ke) {
            throw new HTTPException(ke);
        } catch (NoSuchAlgorithmException nsae) {
            throw new HTTPException(nsae);
        } catch (KeyManagementException kme) {
            throw new HTTPException(kme);
        } catch (UnrecoverableEntryException uee) {
            throw new HTTPException(uee);
        }
    }

    //////////////////////////////////////////////////
    // Debug interface

    // Provide a way to kill everything at the end of a Test

    // When testing, we need to be able to clean up
    // all existing sessions because JUnit can run all
    // test within a single jvm.
    static List<HTTPSession> sessionList = null; // List of all HTTPSession instances

    // only used when testing flag is set
    static public boolean TESTING = false; // set to true during testing, should be false otherwise

    static protected synchronized void kill()
    {
        if(sessionList != null) {
            for(HTTPSession session : sessionList) {
                session.close();
            }
            sessionList.clear();
            // Rebuild the connection manager
            connmgr.shutdown();
            connmgr = new PoolingHttpClientConnectionManager();
            setGlobalThreadCount(DFALTTHREADCOUNT);
        }
    }

    // If we are testing, then track the sessions for kill
    static protected synchronized void track(HTTPSession session)
    {
        if(sessionList == null)
            sessionList = new ArrayList<HTTPSession>();
        sessionList.add(session);
    }

    synchronized static public void debugHeaders(boolean print)
    {
        if(dbgreq.size() == 0)
            dbgreq.add((HTTPUtil.InterceptRequest) new HTTPUtil.InterceptRequest().setPrint(print));
        if(dbgrsp.size() == 0)
            dbgrsp.add((HTTPUtil.InterceptResponse) new HTTPUtil.InterceptResponse().setPrint(print));

    }

    static public void
    debugReset()
    {
        dbgreq.clear();
        dbgrsp.clear();
    }

    static public HTTPUtil.InterceptRequest
    debugRequestInterceptor()
    {
        if(dbgreq != null)
            for(HttpRequestInterceptor hri : dbgreq) {
                if(hri instanceof HTTPUtil.InterceptRequest)
                    return ((HTTPUtil.InterceptRequest) hri);
            }
        return null;
    }

    static public HTTPUtil.InterceptResponse
    debugResponseInterceptor()
    {
        if(dbgrsp != null)
            for(HttpResponseInterceptor hri : dbgrsp) {
                if(hri instanceof HTTPUtil.InterceptResponse)
                    return ((HTTPUtil.InterceptResponse) hri);
            }
        return null;
    }

    //////////////////////////////////////////////////
    // KeyStore Management

    // Provide for backward compatibility
    // through the -D properties

    static synchronized void
    setGlobalKeyStoreFromD()
    {
        String keypassword = cleanproperty("keystorepassword");
        String keypath = cleanproperty("keystore");
        String trustpassword = cleanproperty("truststorepassword");
        String trustpath = cleanproperty("truststore");
        try {
            if(keypath != null || trustpath != null) { // define conditionally
                // Load the stores
                truststore = KeyStore.getInstance(KeyStore.getDefaultType());
                try (FileInputStream instream = new FileInputStream(new File(trustpath))) {
                    truststore.load(instream, trustpassword.toCharArray());
                    keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                }
                try (FileInputStream instream = new FileInputStream(new File(keypath))) {
                    keystore.load(instream, keypassword.toCharArray());
                }
                HTTPSession.keypassword = keypassword;
                HTTPSession.trustpassword = trustpassword;
            }
        } catch (IOException
            | NoSuchAlgorithmException
            | CertificateException
            | KeyStoreException
            ex) {
            log.error("Illegal -D keystore parameters: " + ex.getMessage());
        }

    }

    protected Settings
    merge(Settings globalsettings, Settings localsettings)
    {
        // merge global and local settings; local overrides global.
        Settings merge = new Settings();
        for(String key : globalsettings.getNames()) {
            merge.setParameter(key, globalsettings.getParameter(key));
        }
        for(String key : localsettings.getNames()) {
            merge.setParameter(key, localsettings.getParameter(key));
        }
        return merge;
    }

}

