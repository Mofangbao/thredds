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

import java.io.*;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.*;

import org.apache.http.*;
import org.apache.http.auth.AuthScope;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.*;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.util.EntityUtils;

import static org.apache.http.auth.AuthScope.*;
import static ucar.httpservices.HTTPSession.*;

/**
 * HTTPMethod is the encapsulation of specific
 * kind of server request: GET, HEAD, POST, etc.
 * The general processing sequence is as follows.
 * <ol>
 * <li> Create an HTTPMethod object using one of the
 * methods of HTTPFactory (e.g. HTTPFactory.Get()).
 * <p/>
 * <li> Set parameters and headers of the returned HTTPMethod instance.
 * <p/>
 * <li> Invoke the execute() method to actually make
 * the request.
 * <p/>
 * <li> Extract response headers.
 * <p/>
 * <li> Extract any body of the response in one of several forms:
 * an Inputstream, a byte array, or a String.
 * <p/>
 * <li> Close the method.
 * </ol>
 * In practice, one one has an HTTPMethod instance, one can
 * repeat the steps 2-5. Of course this assumes that one is
 * doing the same kind of action (e.g. GET).
 * <p/>
 * The arguments to the factory method are as follows.
 * <ul>
 * <li> An HTTPSession instance (optional).
 * <p/>
 * <li> A URL.
 * </ul>
 * An HTTPMethod instance is assumed to be operating in the context
 * of an HTTPSession instance as specified by the session argument.
 * If not present, the HTTPMethod instance will create a session
 * that will be reclaimed when the method is closed
 * (see the discussion about one-shot operation below).
 * <p/>
 * Method URLs may be specified in any of three ways.
 * <ol>
 * <li> It may be inherited from the URL specified when
 * the session was created.
 * <p/>
 * <li> It may be specified as part of the HTTPMethod
 * constructor (via the factory). If none is specified,
 * then the session URL is used.
 * <p/>
 * <li> It may be specified as an argument to the
 * execute() method. If none is specified, then
 * the factory constructor URL is used (which might,
 * in turn have come from the session).
 * </ol>
 * <p/>
 * Legal url arguments to HTTPMethod are constrained by the URL
 * specified in creating the HTTPSession instance, if any.  If
 * the session was constructed with a specified URL, then any
 * url specified to HTTMethod (via the factory or via
 * execute()) must be "compatible" with the session URL). The
 * term "compatible" basically means that the session url, as a
 * string, must be a prefix of the specified method url.  This
 * maintains the semantics of the Session but allows
 * flexibility in accessing data from the server.
 * <p/>
 * As an example, the session url might be
 * "http://motherlode.ucar.edu" and the method url might be a
 * more specific URL such as
 * http://motherlode.ucar.edu/path/file.nc.dds.
 * <p/>
 * <u>One-Shot Operation:</u>
 * A reasonably common use case is when a client
 * wants to create a method, execute it, get the response,
 * and close the method. For this use case, creating a session
 * and making sure it gets closed can be a tricky proposition.
 * To support this use case, HTTPMethod supports what amounts
 * to a one-shot use. The steps are as follows:
 * <ol>
 * <li> HTTPMethod method = HTTPFactory.Get(<url string>); note
 * that this implicitly creates a session internal to the
 * method instance.
 * <p/>
 * <li> Set any session parameters or headers using method.getSession().setXXX
 * <p/>
 * <li> Set any parameters and headers on method
 * <p/>
 * <li> method.execute();
 * <p/>
 * <li> Get any response method headers
 * <p/>
 * <li> InputStream stream = method.getResponseBodyAsStream()
 * <p/>
 * <li> process the stream
 * <p/>
 * <li> stream.close()
 * </ol>
 * There are several things to note.
 * <ul>
 * <li> Closing the stream will close the underlying method, so it is not
 * necessary to call method.close().
 * <li> However, if you, for example, get the response body using getResponseBodyAsString(),
 * then you need to explicitly call method.close().
 * <li> Closing the method (directly or through stream.close())
 * will close the one-shot session created by the method.
 * </ul>
 * <p/>
 * It is important to note that as the move to Apache Httpclient 4.3.x,
 * the HttpRequestBase objects are generally immutable. This means that
 * the relevant info must be stored and created on demand.
 * <p/>
 * Note: is this class needed any more since HTTPSession does most of the work?
 */

public class HTTPMethod implements AutoCloseable
{
    //////////////////////////////////////////////////
    // Instance fields

    protected HTTPSession session = null;
    protected boolean localsession = false;
    protected URL methodurl = null;
    protected List<Header> headers = new ArrayList<Header>();
    protected HttpEntity content = null;
    protected HTTPSession.Methods methodclass = null;
    protected HTTPMethodStream methodstream = null; // wrapper for strm
    protected boolean closed = false;

    // Ref to httpsession execution context
    HttpClientContext execcontext = null;
    HttpRequest request = null;
    HttpResponse response = null;

    // Note: currently we do no cache e.g. RequestConfig and Request
    // So: Created on demand
    //protected RequestConfig config = null;
    //protected HttpRequestBase request = null;
    //protected HttpResponse response = null;

    //////////////////////////////////////////////////
    // Constructor(s)

    public HTTPMethod(HTTPSession.Methods m)
            throws HTTPException
    {
        this(m, null, null);
    }

    public HTTPMethod(HTTPSession.Methods m, String url)
            throws HTTPException
    {
        this(m, null, url);
    }

    public HTTPMethod(HTTPSession.Methods m, HTTPSession session, String u)
            throws HTTPException
    {
        URL url = null;
        if(u == null && session != null)
            url = session.getURL();
        else try {
            url = new URL(u);
        } catch (MalformedURLException mue) {
            throw new HTTPException("Malformed URL: " + u, mue);
        }
        if(session == null) {
            session = HTTPFactory.newSession(url.toString());
            localsession = true;
        }
        this.session = session;
        url = HTTPUtil.removeprincipal(url);
        this.methodurl = url;
        this.session.addMethod(this);
        this.methodclass = m;
    }

    //////////////////////////////////////////////////
    // Execution support

    /**
     * Create a request, add headers, and content,
     * then send to HTTPSession to do the bulk of the work.
     */
    public int execute()
            throws HTTPException
    {
        if(closed)
            throw new HTTPException("HTTPMethod: attempt to execute closed method");
        if(this.methodurl == null)
            throw new HTTPException("HTTPMethod: no url specified");
        if(!localsession && !sessionCompatible(this.methodurl))
            throw new HTTPException("HTTPMethod: session incompatible url: " + this.methodurl.toString());

        HttpRequestBase request = createRequest();

        // Add any defined headers
        if(headers.size() > 0) {
            for(Header h : headers) {
                request.addHeader(h);
            }
        }

        setcontent(request);

        this.execcontext = session.execute(request);
        this.request = this.execcontext.getRequest();
        this.response = this.execcontext.getResponse();
        int code = this.response.getStatusLine().getStatusCode();
        return code;
    }

    protected HttpRequestBase
    createRequest()
            throws HTTPException
    {
        HttpRequestBase method = null;

        if(this.methodurl == null)
            throw new HTTPException("No url specified");

        switch (this.methodclass) {
        case Put:
            method = new HttpPut(this.methodurl.toString());
            break;
        case Post:
            method = new HttpPost(this.methodurl.toString());
            break;
        case Get:
            method = new HttpGet(this.methodurl.toString());
            break;
        case Head:
            method = new HttpHead(this.methodurl.toString());
            break;
        case Options:
            method = new HttpOptions(this.methodurl.toString());
            break;
        default:
            break;
        }
        return method;
    }

    protected void
    setcontent(HttpRequestBase request)
    {
        switch (this.methodclass) {
        case Put:
            if(this.content != null)
                ((HttpPut) request).setEntity(this.content);
            break;
        case Post:
            if(this.content != null)
                ((HttpPost) request).setEntity(this.content);
            break;
        case Head:
        case Get:
        case Options:
        default:
            break;
        }
        this.content = null; // do not reuse
    }

    //////////////////////////////////////////////////

    /**
     * Calling close will force the method to close, and will
     * force any open stream to terminate. If the session is local,
     * Then that too will be closed.
     */
    public synchronized void
    close()
    {
        if(closed)
            return; // multiple calls ok
        closed = true; // mark as closed to prevent recursive calls
        if(methodstream != null) {
            try {
                methodstream.close();
            } catch (IOException ioe) {
                throw new IllegalStateException();
            }
            methodstream = null;
        }
        if(session != null) {
            session.removeMethod(this);
            if(localsession) {
                session.close();
                session = null;
            }
        }
    }

    //////////////////////////////////////////////////
    // Accessors

    public String getPath()
    {
        return methodurl.getPath();
    }

    public int getStatusCode()
    {
        return ((this.response == null) ? 0 : this.response.getStatusLine().getStatusCode());
    }

    public String getStatusLine()
    {
        return this.response == null ? null
                : this.response.getStatusLine().toString();
    }

    public boolean canHoldContent()
    {
        if(this.request == null)
            return false;
        return !(this.request instanceof HttpHead);
    }

    public InputStream getResponseBodyAsStream()
    {
        return getResponseAsStream();
    }

    public InputStream getResponseAsStream()
    {
        if(closed)
            throw new IllegalStateException("HTTPMethod: method is closed");
        if(this.methodstream != null) { // duplicate: caller's problem
            HTTPSession.log.warn("HTTPRequest.getResponseBodyAsStream: Getting method stream multiple times");
        } else { // first time
            HTTPMethodStream stream = null;
            try {
                if(this.response == null) return null;
                stream = new HTTPMethodStream(this.response.getEntity().getContent(), this);
            } catch (Exception e) {
                stream = null;
            }
            this.methodstream = stream;
        }
        return this.methodstream;
    }

    public byte[] getResponseAsBytes(int maxbytes)
    {
        byte[] contents = getResponseAsBytes();
        if(contents != null && contents.length > maxbytes) {
            byte[] result = new byte[maxbytes];
            System.arraycopy(contents, 0, result, 0, maxbytes);
            contents = result;
        }
        return contents;
    }

    public byte[] getResponseAsBytes()
    {
        if(closed)
            throw new IllegalStateException("HTTPMethod: method is closed");
        byte[] content = null;
        if(this.response != null)
            try {
                content = EntityUtils.toByteArray(this.response.getEntity());
            } catch (Exception e) {/*ignore*/}
        return content;
    }

    public String getResponseAsString(String charset)
    {
        if(closed)
            throw new IllegalStateException("HTTPMethod: method is closed");
        String content = null;
        if(this.response != null)
            try {
                Charset cset = Charset.forName(charset);
                content = EntityUtils.toString(this.response.getEntity(), cset);
            } catch (Exception e) {
                throw new IllegalArgumentException(e.getMessage());
            }
        close();//getting the response will disallow later stream
        return content;
    }

    public String getResponseAsString()
    {
        return getResponseAsString("UTF-8");
    }

    public void setMethodHeaders(List<Header> headers) throws HTTPException
    {
        try {
            for(Header h : headers) {
                this.headers.add(h);
            }
        } catch (Exception e) {
            throw new HTTPException(e);
        }
    }

    public void setRequestHeader(String name, String value) throws HTTPException
    {
        setRequestHeader(new BasicHeader(name, value));
    }

    public void setRequestHeader(Header h) throws HTTPException
    {
        try {
            headers.add(h);
        } catch (Exception e) {
            throw new HTTPException("cause", e);
        }
    }

    public Header getRequestHeader(String name)
    {
        if(this.request == null)
            return null;
        try {
            return (this.request.getFirstHeader(name));
        } catch (Exception e) {
            return null;
        }
    }

    public Header[] getRequestHeaders()
    {
        if(this.request == null)
            return null;
        try {
            Header[] hs = this.request.getAllHeaders();
            return hs;
        } catch (Exception e) {
            return null;
        }
    }

    public Header getResponseHeader(String name)
    {
        try {
            return this.response.getFirstHeader(name);
        } catch (Exception e) {
            return null;
        }
    }

    public Header[] getResponseHeaders()
    {
        try {
            Header[] hs = this.response.getAllHeaders();
            return hs;
        } catch (Exception e) {
            return null;
        }
    }

    public void setRequestContent(HttpEntity content)
    {
        this.content = content;
    }

    //todo:
    // public void setMultipartRequest(Part[] parts) throws HTTPException
    //{
    //    multiparts = new Part[parts.length];
    //    for(int i = 0;i < parts.length;i++) {
    //        multiparts[i] = parts[i];
    //    }
    //}

    public String getCharSet()
    {
        return "UTF-8";
    }

    public String getName()
    {
        return this.request == null ? null : request.getRequestLine().getMethod();
    }

    public URL getURL()
    {
        return this.methodurl;
    }

    public String getProtocolVersion()
    {
        String ver = null;
        if(request != null) {
            ver = request.getProtocolVersion().toString();
        }
        return ver;
    }

    public String getStatusText()
    {
        return getStatusLine();
    }

    public static Set<String> getAllowedMethods()
    {
        HttpResponse rs = new BasicHttpResponse(new ProtocolVersion("http", 1, 1), 0, "");
        Set<String> set = new HttpOptions().getAllowedMethods(rs);
        return set;
    }

    // Convenience methods to minimize changes elsewhere

    public void setFollowRedirects(boolean tf)
    {
        //ignore ; always done
    }

    public void
    setAllowCompression()
    {
        if(this.session != null)
            this.session.setAllowCompression();
    }

    public String getResponseCharSet()
    {
        return "UTF-8";
    }


    public HTTPSession
    getSession()
    {
        return this.session;
    }

    public boolean
    isSessionLocal()
    {
        return this.localsession;
    }

    public boolean hasStreamOpen()
    {
        return methodstream != null;
    }

    public boolean isClosed()
    {
        return this.closed;
    }

    /**
     * Test that the given url is "compatible" with the
     * session specified dataset. Compatible means:
     * 1. remove any query
     * 2. HTTPAuthStore.compatibleURL must return true;
     * <p/>
     * * @param url  to test for compatibility
     *
     * @return
     */
    protected boolean sessionCompatible(URL other)
    {
        // Remove any trailing constraint
        URL sessionurl = this.session.getURL();
        if(sessionurl == null) return false; // method must have realm url
        return compatibleURL(sessionurl, other);
    }


    /**
     * Define URI compatibility.
     * Currently, it is assumed that two urls are compatible if and only if
     * they have the same host and port
     */
    static protected boolean compatibleURL(URL u1, URL u2)
    {
        if(u1 == u2) return true;
        if((u1 == null) ^ (u2 == null))
	    return false;

        return u1.getHost().equals(u2.getHost())
                    && u1.getPort() == u2.getPort();
    }

    //////////////////////////////////////////////////
    // debug interface

    public HttpRequest
    debugRequest()
    {
        return this.request;
    }

    public HttpResponse
    debugResponse()
    {
        return this.response;
    }

}
