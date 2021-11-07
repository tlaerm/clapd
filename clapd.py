"""
"""

# Created on 2021
#
# Author: Thomas Lärm
# Based in large parts on work by Giovanni Cannata for https://github.com/cannatag/ldap3
#
# Copyright 2021 Thomas Lärm
#
# This file is part of clapd.
#
# clapd is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# clapd is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with clapd in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

from pprint import pformat
import socket,struct,sys,time
import hashlib
import logging, ssl, os, yaml, redis
from datetime import date, datetime
from ber import *
from util import compute_ldap_message_size
from pickle import loads, dumps

LOGLEVELS = {
    "info": logging.INFO,
    "debug": logging.DEBUG,
    "warning": logging.WARNING,
    "error": logging.ERROR
}

  
with open(os.getcwd()+"/configuration.yaml", 'r', encoding='utf8') as ymlfile:
    cfg = yaml.load(ymlfile, Loader=yaml.SafeLoader)

cachedb = redis.Redis(host=cfg['redis']['host'], port=cfg['redis']['port'], db=0)
#TODO optional configuration via environment variables

if cfg['base']['flushdb']:
  logging.info("Flushing cachedb")
  cachedb.flushall()
  
print("Setting loglevel to "+ str(LOGLEVELS[cfg['base']['loglevel']]))

logging.basicConfig(level=LOGLEVELS[cfg['base']['loglevel']], format='%(asctime)s - %(levelname)s - %(message)s')
 
clientsock = False

class Cache:
    def __init__(self, cachedb):
        self.cachedb = cachedb
    
    def cacheBind(self, bindHash, response, request):
        self.cachedb.set(str(bindHash), dumps(response))
        self.cachedb.set(str(bindHash)+"_ttl", float(time.time()))
        self.cachedb.set(str(bindHash)+"_request", dumps(request))
        logging.debug("CACHED bind response with bindHash "+str(bindHash))
    
    def cacheResult(self, requestHash, bindHash, response,):
        self.cachedb.set(str(requestHash), dumps(response))
        self.cachedb.set(str(requestHash)+"_ttl", float(time.time()))
        self.cachedb.set(str(requestHash)+"_bindHash", dumps(bindHash))
        logging.info("CACHED search result with requestHash "+str(requestHash))
        return True

    def getBind(self, bindHash, serversock):
        if self.cachedb.get(str(bindHash)):
            bindResponse = self.cachedb.get(str(bindHash))
            logging.debug("FOUND cached response for bindHash " + str(bindHash))
            if (float(self.cachedb.get(str(bindHash)+"_ttl")) > (time.time() - cfg['cache']['bind']['ttl'])) or (serversock == False):
                logging.debug("CACHED response for with good TTL for bindHash " + str(bindHash))
                return loads(bindResponse)
            else:
                return False
        else:
            return False

    def getBindRequest(self, bindHash):
        if self.cachedb.get(str(bindHash)+"_request"):
            request = self.cachedb.get(str(bindHash)+"_request")
            return loads(request)   
 
    def getBindRequestForSearch(self, requestHash):
        if self.cachedb.get(str(requestHash)+"_bindHash"):
            bindHash = loads(self.cachedb.get(str(requestHash)+"_bindHash"))
            logging.debug("GOT Bind request "+str(bindHash)+" for search request hash " + str(requestHash))
            return self.getBindRequest(bindHash)
        else:
            return False

    def getResult(self, requestHash, bindHash, serversock):
        if self.cachedb.get(str(requestHash)):
            searchResponse = self.cachedb.get(str(requestHash))
            logging.debug("FOUND cached response for requestHash " + str(requestHash))
            if ((float(self.cachedb.get(str(requestHash)+"_ttl")) > (time.time() - cfg['cache']['bind']['ttl'])) or (serversock == False)) and (self.cachedb.get(str(requestHash)+"_bindHash") == dumps(bindHash)):
                logging.debug("CACHED response for with good TTL for requestHash " + str(requestHash))
                return loads(searchResponse)
            else:
                return False
        else:
            return False

class LDAPRequestHandler:
    def __init__(self, clientsock, serversock, cachedb, bindHash, bindAnsweredFromCache = False):
        self.clientsock = clientsock
        self.serversock = serversock
        self.cache = Cache(cachedb)
        self.cachedb = cachedb
        self.bound = False

        self.bindAnsweredFromCache = bindAnsweredFromCache
        if bindHash:
            self.bindHash = bindHash
        receivingRequests = True
        while receivingRequests:
            logging.debug("Trying to receive more data")
            self.requests = self.receiveLDAP(self.clientsock)
            if self.requests:
                self.response = []
                logging.debug("----------------------------------------")
                logging.debug("HANDLING request with protocolOP " + str(self.decodeLDAPmessages(self.requests)[0]['protocolOp']))
                self.REQUESTHANDLERS[self.decodeLDAPmessages(self.requests)[0]['protocolOp']](self)
            else:
                logging.debug("Nothing more received")
                receivingRequests = False

        self.__del__()
            
    def __del__(self):
        logging.info("Transaction complete")

    def handleBindRequest(self):
        logging.info("HANDLING Bind Request")
        self.bindHash = hashlib.md5(str(self.decodeLDAPmessages(self.requests)).encode()).hexdigest()
        messageID = self.decodeLDAPmessages(self.requests)[0]['messageID']
        logging.debug("with bindHash " + self.bindHash)
        logging.debug("with messageID " + str(messageID))

        logging.debug("BIND REQUEST: "+pformat(self.decodeLDAPmessages(self.requests)))
        
        if self.cache.getBind(self.bindHash, self.serversock):
            self.response = self.cache.getBind(self.bindHash, self.serversock)
            self.bindAnsweredFromCache = True
            logging.info("GOT bind response from cache")
        else:
            if self.serversock:
                self.sendLDAP(self.requests, self.serversock)
                self.response = self.receiveLDAP(self.serversock)
                logging.debug("BIND RESPONSE: "+pformat(self.decodeLDAPmessages(self.response)))
                self.cache.cacheBind(self.bindHash, self.response, self.requests)
                bindResultCode = self.decodeLDAPmessages(self.response)[0]['payload'][0][3]
                if bindResultCode == 0:
                    self.bound = True
                logging.info("GOT bind response from server "+cfg['server']['host']+" with Result Code "+ str(bindResultCode))
            else:
                return False
        self.RESPONSEHANDLERS[self.decodeLDAPmessages(self.response)[0]['protocolOp']](self)

    def handleBindResponse(self):
        logging.info("HANDLING Bind Response")
        logging.debug("Received response: "+ pformat(self.decodeLDAPmessages(self.response)) +" of type "+ str(type(self.response)))
        self.sendLDAP(self.response, self.clientsock)
        logging.info("ANSWERED bind request")
    
    def replayBindRequest(self):
        logging.info("REPLAYING bind request with bindHash "+ self.bindHash)
        cachedBindRequest = self.cache.getBindRequestForSearch(self.requestHash)
        if not cachedBindRequest:
            cachedBindRequest = self.cache.getBindRequest(self.bindHash)
        logging.debug("GOT cached Bind request: "+ pformat(self.decodeLDAPmessages(cachedBindRequest)))
        self.sendLDAP(cachedBindRequest, self.serversock)
        self.response = self.receiveLDAP(self.serversock)
        bindResultCode = self.decodeLDAPmessages(self.response)[0]['payload'][0][3]
        logging.debug("Received BIND response: "+ pformat(self.decodeLDAPmessages(self.response)) +"with Result Code " + str(bindResultCode))
        self.cache.cacheBind(self.bindHash, self.response, cachedBindRequest)
       
        if bindResultCode == 0:
            self.bound = True

    def handleUnbindRequest(self):
        logging.info("HANDLING Unbind Request")
        self.bound = False
        self.sendLDAP(self.requests, self.serversock)
        
    def handleSearchRequest(self):
        logging.info("HANDLING Search Request")
        self.requestHash = hashlib.md5(str(self.decodeLDAPmessages(self.requests)).encode()).hexdigest()
        messageID = self.decodeLDAPmessages(self.requests)[0]['messageID']
        
        logging.debug("with requestHash " + self.requestHash)
        logging.debug("with messageID " + str(messageID))
        logging.debug("SEARCH REQUEST: "+pformat(self.decodeLDAPmessages(self.requests)))
        if self.cache.getResult(self.requestHash, self.bindHash, self.serversock):
            self.response = self.cache.getResult(self.requestHash, self.bindHash, self.serversock)
            logging.info("GOT search response from cache")
            logging.debug("Cached SEARCH response: "+ pformat(self.decodeLDAPmessages(self.response)) +" of type "+ str(type(self.response)))            
            self.RESPONSEHANDLERS[self.decodeLDAPmessages(self.response)[0]['protocolOp']](self)
        elif self.serversock:
            if self.bindAnsweredFromCache and not self.bound:
                self.replayBindRequest()
            self.sendLDAP(self.requests, self.serversock)
            self.response = self.receiveLDAP(self.serversock)
            protocolOp = self.decodeLDAPmessages(self.response)[-1]['protocolOp']
            lastResponse = []

            while protocolOp != 5:
                lastResponse = self.receiveLDAP(self.serversock)
                self.response += lastResponse
                protocolOp = self.decodeLDAPmessages(self.response)[-1]['protocolOp']
                # logging.debug("\n protocolOp" + str(protocolOp))
            self.cache.cacheResult(self.requestHash, self.bindHash, self.response)
            logging.info("GOT search response from server "+cfg['server']['host'])
            self.RESPONSEHANDLERS[self.decodeLDAPmessages(self.response)[-1]['protocolOp']](self)
        else: 
            self.response = []

    def handleSearchResult(self):
        self.sendLDAP(self.response, self.clientsock)
        logging.debug("Received SEARCH response: "+ pformat(self.decodeLDAPmessages(self.response)) +" of type "+ str(type(self.response)))
        logging.info("ANSWERED search request")

    def decodeLDAPmessages(self,messages):
        decodedMessages = []
        for message in messages:
            decodedMessages.append(decode_message_fast(message))
        return decodedMessages

    def sendLDAP(self,messages, sock):
        if sock:
            for message in messages:
                sock.send(message)

    def receiveLDAP(self,sock):
        if not sock:
            return []
        messages = []
        receiving = True
        unprocessed = b''
        data = b''
        socket_size = 4096
        get_more_data = True
        sock.settimeout(1)
        while receiving:
            if get_more_data:
                try:
                    data = sock.recv(socket_size)
                except (OSError, AttributeError) as e:
                    logging.error(e)
                    return False
                except KeyboardInterrupt:
                    sock.close
                unprocessed += data
            if len(data) > 0:
                length = compute_ldap_message_size(unprocessed)
                if length == -1:  # too few data to decode message length
                    get_more_data = True
                    continue
                if len(unprocessed) < length:
                    get_more_data = True
                else:
                    messages.append(unprocessed[:length])
                    unprocessed = unprocessed[length:]
                    get_more_data = False
                    if len(unprocessed) == 0:
                        receiving = False
            else:
                receiving = False
        if len(messages) > 0:
            return messages
        else:
            return False
            
    REQUESTHANDLERS = { 
        0: handleBindRequest,
        2: handleUnbindRequest,
        3: handleSearchRequest
    }
    RESPONSEHANDLERS = { 
        1: handleBindResponse,
        4: handleSearchResult,
        5: handleSearchResult
    }

def logformat(content):
    return pprint.pformat(content).split('\n')

if __name__=='__main__':
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.bind(('',cfg['base']['port']))
    sock.listen(5)
    logging.info('clapd listening on port ' + str(cfg['base']['port']))
    offline = False
    offlineFrom = 0
    while True:
        clientsock,address=sock.accept()
        logging.info("Connection from " + str(address))
        serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serversock.settimeout(1)

        if not offline or (offline and offlineFrom + cfg['server']['offlineRetry'] < time.time()):
            try:
                serversock.connect((cfg['server']['host'], cfg['server']['port']))
                logging.debug("CONNECT to server successful")
                offline = False
                offlineFrom = 0
            except:
                logging.info("CONNECT failed - switching to offline mode")
                serversock = False
                offlineFrom = time.time()
                offline = True
        else:
            serversock = False
            offline = True

        if cfg['server']['protocol'] == 'ldaps':
            context = ssl.create_default_context()
            serversock = context.wrap_socket(serversock, server_hostname=cfg['server']['host'])
        handler = LDAPRequestHandler(clientsock, serversock, cachedb, False)
