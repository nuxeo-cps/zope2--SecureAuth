##############################################################################
#
# Copyright (c) 2001 Zope Corporation and Contributors. All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.0 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################
""" Secure Auth: Enable cookies for non-cookie user folders.

$Id$
"""

from base64 import encodestring
from urllib import quote, unquote
from DateTime import DateTime
from AccessControl import ClassSecurityInfo
import Globals
from Globals import HTMLFile, DTMLFile
from zLOG import LOG, ERROR, DEBUG, INFO
import sys
import time
import threading

from ZPublisher.HTTPRequest import HTTPRequest

from ZTUtils import make_query

from Products.CMFCore.utils import getToolByName
from Products.CMFCore.CookieCrumbler import CookieCrumbler, ResponseCleanup

from Products.Sessions.BrowserIdManager import BROWSERID_MANAGER_NAME

from BTrees.OOBTree import OOBTree

from persistent.cPersistence import Persistent

# Constants.
ATTEMPT_DISABLED = -1  # Disable cookie crumbler
ATTEMPT_NONE = 0       # No attempt at authentication
ATTEMPT_LOGIN = 1      # Attempt to log in
ATTEMPT_RESUME = 2     # Attempt to resume session

DEBUGGING = 0

# global Request Counter
# Used to trigger periodicaly TimeOut cleanning
global RequestCounter
RequestCounter = 0

global LastTimeOutCheckTime
LastTimeOutCheckTime=time.time()

global LastCounterCheckTime
LastCounterCheckTime=time.time()

global glogged_list
glogged_list={}

global AvNbRequestsPerHour
AvNbRequestsPerHour=0

try:
    from zExceptions import Redirect
except ImportError:
    # Pre Zope 2.7
    Redirect = 'Redirect'


class PersistentLoggedList(Persistent):
    """
    This class defines a container used to store persistant logged_list.
    This container is accessed as a dictionnary that stores a persistent
    list of Auth tokens

    To avoid Persistence Conflict error, a OOBTree is used and the
    "application level conflict error resolution interface" is implemented
    """

    _Internal_lock = threading.RLock()

    def __init__(self):
        self.BTreeDico=OOBTree()
        self.UpdateTime=time.time()
        self.CleanTime=time.time()


    #
    # Conflict Resolution

    def _p_resolveConflict(self, old, s1, s2):
        """ in case of conflict return merged state """
        try:
            LOG("SecureAuth",DEBUG,"Try to resolve conflict")
            old.update(s1)
            old.update(s2)
        except Exception,e:
            LOG("SecureAuth",DEBUG,"Conflict resolution failed %s " % e)
        except:
            LOG("SecureAuth",DEBUG,"Conflict resolution failed: Unknown error ")
            pass

        return old

    def _p_independent(self):
        # My state doesn't depend on or materially effect the state of
        # other objects.
        return 1


    #
    # Partial Dico Interface

    def __delitem__(self,key):
        self._Internal_lock.acquire()
        try:
            try:
                del self.BTreeDico[key]
                self._NotifyUpdate()
            except:
                pass
        finally:
            self._Internal_lock.release()

    def __getitem__(self,key):
        return self.get(key,None)

    def __setitem__(self,key,value):
        self._Internal_lock.acquire()
        try:
            self.BTreeDico[key]=value
            self._NotifyUpdate()
        finally:
            self._Internal_lock.release()

    def keys(self):
        return self.BTreeDico.keys()

    def has_key(self,key):
        return self.BTreeDico.has_key(key)

    def get(self,key,default_value=None):
        self._Internal_lock.acquire()
        Item=None
        try:
            if key in self.BTreeDico.keys():
                Item=self.BTreeDico.get(key)
            else:
                Item=default_value
        finally:
            self._Internal_lock.release()
            return Item

    def update(self,SrcDico):
        self._Internal_lock.acquire()
        try:
            self.BTreeDico.update(SrcDico)
            self._NotifyUpdate()
        finally:
            self._Internal_lock.release()

    #
    # Specific API

    def _NotifyUpdate(self):
        self._p_changed=1 # not very usefull but meaningfull :)
        self.UpdateTime=time.time()


    def DeleteOldEntries(self,TimeOutValue,SrcDico):
        try:
            LOG("SecureAuth",DEBUG,"ZODB LoggedList Cleaning could begin ???")
            self._Internal_lock.acquire()
            nTime=time.time()
            if (nTime-self.CleanTime)>TimeOutValue:
                LOG("SecureAuth",DEBUG,"ZODB LoggedList Cleanning begins")
                self.BTreeDico.update(SrcDico)
                for k in self.BTreeDico.keys():
                    vList=self.BTreeDico[k]
                    if vList[1]+TimeOutValue<nTime:
                        del self.BTreeDico[k]
                        LOG("SecureAuth",DEBUG,"ZODB LoggedList delete %s" % k)
                self.CleanTime=nTime
                self._NotifyUpdate()
            else:
                LOG("SecureAuth",DEBUG,"ZODB LoggedList Nothing to do")
        finally:
            self._Internal_lock.release()

    def Reset(self):
        try:
            self._Internal_lock.acquire()
            self.BTreeDico=OOBTree()
            self.CleanTime=time.time()
            self._NotifyUpdate()
        finally:
            self._Internal_lock.release()

class SecureAuth (CookieCrumbler):
    """Enable the use of a cookie to keep track of a authentification session.

    The secure auth works the same way the cookie crumbler does : the user is
    identified with a cookie that corresponds to authentification information.

    Cookie Crumbler uses a simple base64 string <login:password> stored on the
    client side.
    Secure Auth uses the _ZopeId (or whatever) to keep track of users and
    associate them a list that stores their authentication information
    ie: [__ac, TimeStamp, Auth_Tocken]

    Secure Auth supports :
        - Basic authentification via FORM
        - X509 Certificats via Apache+Mod_SSL
        - CAS SSO (to be added)

    Secure Auth introduce a User/Server affinity when the auth list is stored
    only in RAM.
    To avoid this, Persistent Session must be activated via ZMI
    (persistence has a performance impact, don't run GC too frequently)
    """

    meta_type = 'Secure Auth'
    security = ClassSecurityInfo()

    _properties = CookieCrumbler._properties + (
                    {'id':'C__TIME_OUT', 'type': 'int', 'mode':'w',
                     'label':'Time out (s)'},
                    {'id':'MOD_CLEAN', 'type': 'int', 'mode':'w',
                 'label':'Time out check frequency (nb of requests)'},
                {'id':'enable_clcert', 'type': 'boolean', 'mode':'w',
                 'label':'Enable certificate based authentication with Apache'},
                {'id':'use_persistant_logged_list', 'type': 'boolean',
             'mode':'w',
             'label':'Stores auth sessions in ZODB to share it between ZEO clients'})

    manage_options=CookieCrumbler.manage_options + (
            {'label': 'Statistics','action': 'manage_viewLoggedLists'},
            )


    token_cookie = '__tc'
    zope_cookie = '_ZopeId'

    auth_cookie = '__ac'
    name_cookie = '__ac_name'
    pw_cookie = '__ac_password'
    persist_cookie = '__ac_persistent'
    auto_login_page = 'login_form'
    logout_page = 'logged_out'
    enable_clcert = 0
    use_persistant_logged_list = 0

    # default TimeOut to 1 hour
    C__TIME_OUT = 60*60
    # default check every 500 requests
    MOD_CLEAN = 500

    # Client Cert Auth
    cl_cert_url = 'secure_auth_uid'
    cl_cert_header = 'CLCRT'

    cert_auth = 'Cert Auth'
    basic_auth = 'Basic Auth'

    # RAM Auth Session Dico
    # Stored in RAM at class level
    # and the lock associated to deal with concurrency
    #
    # Note : There is one logged_list per ZEO instance
    #        This list is not persistant
    logged_list = {}
    _RAM_lock = threading.RLock()


    # ZODB Auth Session Dico
    # is handled by a specific class

    ## Handles RAM logged List modifications
    def delLogged(self, key):
        self._RAM_lock.acquire()
        try:
            try:
                #del self.logged_list[key]
                global glogged_list
                del glogged_list[key]
                LOG("SecureAuth",DEBUG,"Deleting key %s from RAM List" % key)
            except:
                pass
        finally:
            self._RAM_lock.release()

    def addLogged(self, key, value):
        global glogged_list
        self._RAM_lock.acquire()
        try:
            #if self.logged_list.has_key(key):
            if glogged_list.has_key(key):
                # return
                # update RAM
                LOG("SecureAuth",DEBUG,"Updating Auth Session in RAM : %s" % key)
                #self.logged_list[key] = value[:]
                glogged_list[key] = value[:]
            else:
                # insert RAM
                LOG("SecureAuth",DEBUG,"Creating Auth Session in RAM : %s" % key)
                #self.logged_list[key] = value[:]
                glogged_list[key] = value[:]

                # Insert/Update in ZODB too
                if self.use_persistant_logged_list:
                    try:
                        LOG("SecureAuth",DEBUG,"Creating Auth Session in ZODB : %s" % key)
                        pLoggedList=self._getPersistantLoggedList()
                        pLoggedList[key]=value[:]
                    except:
                        LOG("SecureAuth",ERROR,"Unable to Create Session in ZODB : %s" % key)
                        pass # What else to do ???
        finally:
            self._RAM_lock.release()

    def __call__(self, container, req):
        ## Flag the request to avoid a 2nd call
        if getattr(req, '_hook', 0) == 1:
            return
        req._hook = 1
        CookieCrumbler.__call__(self, container, req)

    #
    # ZMI API
    #

    def manage_getRAMLoggedList(self):
        """ return RAM List """
        global glogged_list
        return glogged_list

    def manage_PurgeRAMLoggedList(self,REQUEST):
        """ Clear everything """
        global glogged_list
        glogged_list={}
        REQUEST.RESPONSE.redirect("manage_viewLoggedLists")

    def manage_getZODBLoggedList(self):
        """ return ZODB List """
        return self._getPersistantLoggedList()

    def manage_PurgeZODBLoggedList(self,REQUEST):
        """ Clear everything """
        self._getPersistantLoggedList().Reset()
        REQUEST.RESPONSE.redirect("manage_viewLoggedLists")

    def manage_getRequestStats(self):
        """ return nb of request before garbage collector """
        global RequestCounter
        global AvNbRequestsPerHour
        global LastCounterCheckTime

        nbRequestB4GC= self.MOD_CLEAN - RequestCounter

        TimeSinceLastGC=time.time()-LastTimeOutCheckTime

        NextGCTime=int(self.C__TIME_OUT-TimeSinceLastGC)
        if NextGCTime <= 0 : # Not enought activity
            NextGCTime="???"

        if RequestCounter==0:
            RequestsPerHour=[AvNbRequestsPerHour, AvNbRequestsPerHour]
        else:
            RequestsPerHour=[AvNbRequestsPerHour,int(3600*(RequestCounter/(time.time()-LastCounterCheckTime)))]

        return [ nbRequestB4GC, LastTimeOutCheckTime, NextGCTime, RequestsPerHour]

    manage_viewLoggedLists=DTMLFile('zmi/SAviewLoggedLists',globals())

    # CPS extension

    def _getPersistantLoggedList(self):
        """ give access to persistent loggedlist ; create it if needed """
        try:
            pLoggedList=self.ZODBLoggedList
        except:
            self.ZODBLoggedList=PersistentLoggedList()
            pLoggedList=self.ZODBLoggedList
        return pLoggedList


    def DoTimeOutCheck(self):
        """ handles timeout check on users list
            - Triggers RAM Check when last list check is older than TimeOut
            - Triggers ZODB Check when last list check is older than twice TimeOut

        """
        LOG("SecureAuth",DEBUG,"Entering DoTimeOutCheck")
        self._RAM_lock.acquire()
        try:
            global LastTimeOutCheckTime
            global LastCounterCheckTime
            global RequestCounter
            global glogged_list

            RequestCounter = 0
            ti = time.time()
            LastCounterCheckTime=ti
            if LastTimeOutCheckTime+self.C__TIME_OUT<ti:
                LastTimeOutCheckTime=ti
            else:
                LOG("SecureAuth",DEBUG,"DoTimeOutCheck Nothing to Do : min %s ms before next cleanning" % ((LastTimeOutCheckTime+self.C__TIME_OUT)-ti))
                # self._RAM_lock.release() # not usefull
                return

            # We do the clean up in RAM
            LOG("SecureAuth",DEBUG,"DoTimeOutCheck Cleanning RAM")
            #for l__key in self.logged_list.keys():
            #    if self.logged_list.get(l__key,(ti,ti))[1] < ti:
            #        self.delLogged(l__key)
            for l__key in glogged_list.keys():
                if glogged_list.get(l__key,(ti,ti))[1] < ti:
                    self.delLogged(l__key)


            # Do the check in ZODB too ???
            if self.use_persistant_logged_list:
                try:
                    LOG("SecureAuth",DEBUG,"DoTimeOutCheck Check if ZODB Cleaning is Usefull")
                    pLoggedList=self._getPersistantLoggedList()
                    #pLoggedList.DeleteOldEntries(self.C__TIME_OUT,self.logged_list.copy())
                    pLoggedList.DeleteOldEntries(self.C__TIME_OUT,glogged_list.copy())
                except:
                    pass # What else to do ???
        finally:
            self._RAM_lock.release()

    def getAuthSession(self,req):
        ZC=req.get(self.zope_cookie,None)
        global glogged_list

        if not ZC:
            LOG("SecureAuth",DEBUG,"getAuthSession Exit : no zope_cookie")
            return False

        LOG("SecureAuth",DEBUG,"Check for Auth Session with key %s" % ZC)

        #if self.logged_list.has_key(ZC):
        if glogged_list.has_key(ZC):
            LOG("SecureAuth",DEBUG,"Auth Session found in RAM : %s" % ZC)
            return True
        else:
            LOG("SecureAuth",DEBUG,"Auth Session not found in RAM trying ZODB : %s" % ZC)
            # Try to get a persistent session from ZODB
            try:
                pLoggedList=self._getPersistantLoggedList()
                AuthList=pLoggedList[ZC]
                if AuthList:
                    self.addLogged(ZC, [AuthList[0], time.time() + self.C__TIME_OUT, AuthList[2]])
                    # Update of TimeStamp of entry in ZODB is done indireclty via addLogged
                    LOG("SecureAuth",DEBUG,"Auth Session restaured from ZODB : %s" % ZC)
                    return True
                else:
                    LOG("SecureAuth",DEBUG,"No Auth Session found ZODB : %s" % ZC)
                    return False
            except:
                return False

    def getBrowserIdManager(self):
        """ """
        mgr = getattr(self, BROWSERID_MANAGER_NAME, None)
        if mgr is None:
            raise "Error: BROWSERID_MANAGER_NAME Not Found"
        return mgr


    # Returns flags indicating what the user is trying to do.
    #
    def modifyRequest(self, req, resp):
        global RequestCounter
        global glogged_list
        global AvNbRequestsPerHour
        global LastTimeOutCheckTime
        global LastCounterCheckTime


        # Timeout management
        RequestCounter += 1

        if RequestCounter > self.MOD_CLEAN :
            global AvNbRequestsPerHour
            AvNbRequestsPerHour=int((3600*RequestCounter)/(time.time()-LastCounterCheckTime))
            RequestCounter=0
            self.DoTimeOutCheck()

        if req.__class__ is not HTTPRequest:
            LOG("SecureAuth ATTEMPT_DISABLED",INFO,"req.__class__ value : %s"%req.__class__)
            return ATTEMPT_DISABLED

        if not req.get('REQUEST_METHOD') in ( 'GET', 'PUT', 'POST', 'LOCK', 'UNLOCK' ):
            LOG("SecureAuth ATTEMPT_DISABLED",INFO,"req[ 'REQUEST_METHOD' ] value : %s"%req.get('REQUEST_METHOD'))
            return ATTEMPT_DISABLED

        if req.environ.has_key( 'WEBDAV_SOURCE_PORT' ):
            LOG("SecureAuth ATTEMPT_DISABLED",INFO,"req.environ.has_key( 'WEBDAV_SOURCE_PORT' ) value : %s"%req.environ.has_key( 'WEBDAV_SOURCE_PORT' ))
            return ATTEMPT_DISABLED

        if req._auth and not getattr(req, '_cookie_auth', 0):
            # Using basic auth.
            LOG("SecureAuth ATTEMPT_DISABLED",INFO,"req._auth value : %s"%req._auth)
            LOG("SecureAuth ATTEMPT_DISABLED",INFO,"getattr(req, '_cookie_auth', 0) value : %s"%getattr(req, '_cookie_auth', 0))
            return ATTEMPT_DISABLED
        else:
            ## Attempt to login via client certificate
            cl_cert = req.get(self.cl_cert_url)
            cl_cert_header = req.get('HTTP_' + self.cl_cert_header)
            # XXX: This is a temporary extraction of uid from dn that will be
            # done on the apache side in the future
            if cl_cert_header:
                cl_cert = cl_cert_header.split('=')[-1]
            if self.enable_clcert and cl_cert:
                LOG('SecureAuth', INFO,
                        'Attempt to login via client certificate: %s' % cl_cert)
                ac = encodestring(cl_cert)
                req._auth = 'CLCert %s' % ac
                req._cookie_auth = 1
                resp._auth = 1
                method = self.getCookieMethod('setAuthCookie',
                                              self.defaultSetAuthCookie)
                # Set Zope_cookie
                if req.has_key(self.zope_cookie):
                    tc = req[self.zope_cookie]
                    method( resp, self.token_cookie, quote( tc ) )
                    self.addLogged(quote( tc ),
                            [ac, time.time() + self.C__TIME_OUT,
                             self.cert_auth])
                else:
                    try :
                        tc = self.getBrowserIdManager().getBrowserId(create=1)
                        method( resp, self.token_cookie, quote( tc ) )
                        self.addLogged(quote( tc ),
                                [ac, time.time() + self.C__TIME_OUT,
                                 self.basic_auth])
                    except :
                        if DEBUGGING == 1:
                            LOG("SecureAuth", ERROR, "Failed to get BrowserIdManager.")
                        return ATTEMPT_DISABLED

                #self.delRequestVar(req, self.name_cookie)
                #method( resp, "ZeoClient", quote( tc ) )
                return ATTEMPT_LOGIN


            ## Attempt to Login via login/pass
            if req.has_key(self.pw_cookie) and req.has_key(self.name_cookie):
                # Attempt to log in and set cookies.
                LOG('SecureAuth', INFO, 'Attempt to login via login/passwd')

                name = req[self.name_cookie]
                pw = req[self.pw_cookie]

                # XXX do we need this?
                ##pw = pw.encode('utf_8')

                ac = encodestring('%s:%s' % (name, pw))

                req._auth = 'Basic %s' % ac
                req._cookie_auth = 1
                resp._auth = 1

                #Modified 0 -> 1
##                if req.get(self.persist_cookie, 0):
                if req.get(self.persist_cookie, 1):
                    # Persist the user name (but not the pw or session)
                    ##expires = (DateTime() + 365).toZone('GMT').rfc822()
                    resp.setCookie(self.name_cookie, name, path='/')
                    ##            expires=expires)
                else:
                    # Expire the user name
                    resp.expireCookie(self.name_cookie, path='/')

                method = self.getCookieMethod( 'setAuthCookie'
                                             , self.defaultSetAuthCookie )
                tc=None
                # Set Zope_cookie
                if req.has_key(self.zope_cookie):
                    tc = req[self.zope_cookie]
                    method( resp, self.token_cookie, quote( tc ) )
                    self.addLogged(quote( tc ), [ac, time.time() + self.C__TIME_OUT, self.basic_auth])
                else:
                    try :
                        #Modified req.SESSION.token -> self.getBrowserIdManager().getBrowserId(create=1)
                        tc = self.getBrowserIdManager().getBrowserId(create=1)
                        method( resp, self.token_cookie, quote( tc ) )
                        self.addLogged(quote( tc ), [ac, time.time() + self.C__TIME_OUT, self.basic_auth])
                    except :
                        if DEBUGGING == 1:
                            LOG("SecureAuth", ERROR, "Failed to get BrowserIdManager.")
                        LOG("SecureAuth", ERROR, "Failed to get BrowserIdManager.")
                        return ATTEMPT_DISABLED

                        # XXX return ATTEMPT_DISABLED or _NONE
                        # XXX del cookies

                if DEBUGGING == 1:
                    LOG('SecureAuth', INFO, 'Attempt login, TC: %s'%tc)
                    LOG("Logged_list => ", DEBUG, glogged_list)

                self.delRequestVar(req, self.name_cookie)
                self.delRequestVar(req, self.pw_cookie)
                #method( resp, "ZeoClient", quote( tc ) )
                return ATTEMPT_LOGIN

            elif (req.has_key(self.token_cookie) and self.getAuthSession(req)):
                # Copy __ac to the auth header.

                l__tc = req[self.token_cookie]
                #l__log_list = self.logged_list.get(l__tc)
                l__log_list = glogged_list.get(l__tc)
                # re-add Timeout delay
                l__log_list[1]=time.time() + self.C__TIME_OUT

                ac = unquote(l__log_list[0])

                auth = l__log_list[2]

                if (req.get(self.name_cookie) != ac.decode('base64').split(':')[0]
                    and auth != self.cert_auth):
                    if DEBUGGING == 1:
                        LOG("name_cookie => ",DEBUG,req.get(self.name_cookie))
                        LOG("ac.decode('base64').split(':')[0] => ",DEBUG,ac.decode('base64').split(':')[0])
                    LOG("name_cookie => ",DEBUG,req.get(self.name_cookie))
                    LOG("ac.decode('base64').split(':')[0] => ",DEBUG,ac.decode('base64').split(':')[0])
                    return ATTEMPT_DISABLED

                if auth == self.cert_auth:
                    req._auth = 'CLCert %s' % ac
                else:
                    req._auth = 'Basic %s' % ac

                req._cookie_auth = 1
                resp._auth = 1
                self.delRequestVar(req, self.auth_cookie)
                return ATTEMPT_RESUME

            return ATTEMPT_NONE

    #
    # Public API
    #

    security.declarePublic('certLogin')
    def certLogin(self, REQUEST=None):
        """Method used by apache to perform certificate based login

        Does a simple redirect to the logged_in page.
        """
        if REQUEST is not None:
            came = REQUEST.form.get('came')
            portal = getToolByName(self, 'portal_url').getPortalObject()

            if came is not None:
                return REQUEST.RESPONSE.redirect('%s/logged_in?came_from=%s' %
                        (portal.absolute_url(), came))

            return REQUEST.RESPONSE.redirect(
                    '%s/logged_in' % portal.absolute_url())


    security.declarePublic('getLoginURL')
    def getLoginURL(self, psm=None):
        '''Redirects to the login page
        '''
        if self.auto_login_page:
            req = self.REQUEST
            resp = req['RESPONSE']
            iself = getattr(self, 'aq_inner', self)
            parent = getattr(iself, 'aq_parent', None)
            page = getattr(parent, self.auto_login_page, None)
            if page is not None:
                retry = getattr(resp, '_auth', 0) and '1' or ''
                came_from = req.get('came_from', None)
                if came_from is None:
                    came_from = '%s?%s'%(req['URL'], make_query(req.form))

                url = '%s?came_from=%s&retry=%s&disable_cookie_login__=1' % (page.absolute_url(), quote(came_from), retry)
                if psm != None:
                    url = url + '&portal_status_message=%s' % psm
                return url
        return None

    security.declarePublic('getLogged_list')
    def getLogged_list(self):
        '''Returns logged_list
        '''
        global glogged_list
        return glogged_list

Globals.InitializeClass(SecureAuth)

manage_addSAForm = HTMLFile('zmi/addSA', globals())
manage_addSAForm.__name__ = 'addSA'

def manage_addSA(self, id, REQUEST=None):
    ' '
    ob = SecureAuth()
    ob.id = id
    self._setObject(id, ob)
    if REQUEST is not None:
        return self.manage_main(self, REQUEST)

