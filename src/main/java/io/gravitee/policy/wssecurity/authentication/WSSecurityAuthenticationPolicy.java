/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.wssecurity.authentication;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.util.Maps;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.api.stream.BufferedReadWriteStream;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.gateway.api.stream.SimpleReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequestContent;
import io.gravitee.policy.wssecurity.authentication.configuration.WSSecurityAuthenticationPolicyConfiguration;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.authprovider.api.Authentication;
import io.gravitee.resource.authprovider.api.AuthenticationProviderResource;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class WSSecurityAuthenticationPolicy {

    private static final String WSSECURITY_AUTH_UNAUTHORIZED = "WSSECURITY_AUTH_UNAUTHORIZED";

    private final NamespaceContext namespaceContext = new NamespaceContext() {
        private final static String SOAP_NAMESPACE_PREFIX = "soapenv";
        private final static String SOAP_NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/";

        private final static String WSSEC_NAMESPACE_PREFIX = "wsse";
        private final static String WSSEC_NAMESPACE = "http://schemas.xmlsoap.org/ws/2003/06/secext";

        @Override
        public String getNamespaceURI(String prefix) {
            if (SOAP_NAMESPACE_PREFIX.equals(prefix)) {
                return SOAP_NAMESPACE;
            } else if (WSSEC_NAMESPACE_PREFIX.equals(prefix)) {
                return WSSEC_NAMESPACE;
            }

            return null;
        }

        @Override
        public String getPrefix(String namespaceURI) {
            return null;
        }

        @Override
        public Iterator getPrefixes(String namespaceURI) {
            return null;
        }
    };

    private final static String USERNAME_VARIABLE = "username";

    /**
     * WS Security authentication policy configuration
     */
    private final WSSecurityAuthenticationPolicyConfiguration wsSecurityAuthenticationPolicyConfiguration;

    public WSSecurityAuthenticationPolicy(WSSecurityAuthenticationPolicyConfiguration wsSecurityAuthenticationPolicyConfiguration) {
        this.wsSecurityAuthenticationPolicyConfiguration = wsSecurityAuthenticationPolicyConfiguration;
    }

    @OnRequestContent
    public ReadWriteStream onRequestContent(Request request, ExecutionContext executionContext, PolicyChain policyChain) {
        return new BufferedReadWriteStream() {

            Buffer buffer = Buffer.buffer();

            @Override
            public SimpleReadWriteStream<Buffer> write(Buffer content) {
                buffer.appendBuffer(content);
                return this;
            }

            @Override
            public void end() {
                if (buffer.length() > 0) {
                    try {
                        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                        factory.setNamespaceAware(true);
                        DocumentBuilder builder = factory.newDocumentBuilder();
                        Document doc = builder.parse(new java.io.ByteArrayInputStream(buffer.getBytes()));
                        XPath xpath = XPathFactory.newInstance().newXPath();
                        xpath.setNamespaceContext(namespaceContext);

                        XPathExpression expr = xpath.compile("//*[local-name()='Envelope']//*[local-name()='Header']//*[local-name()='Security']//*[local-name()='UsernameToken']//*[local-name()='Username']//text() | //*[local-name()='Envelope']//*[local-name()='Header']//*[local-name()='Security']//*[local-name()='UsernameToken']//*[local-name()='Password']//text()");
                        Object result = expr.evaluate(doc, XPathConstants.NODESET);
                        NodeList nodes = (NodeList) result;

                        if (nodes.getLength() >= 2) {
                            // Extract credentials
                            String username = nodes.item(0).getNodeValue();
                            String password = nodes.item(1).getNodeValue();

                            AtomicBoolean authenticated = new AtomicBoolean(false);

                            Iterator<String> authProviders = wsSecurityAuthenticationPolicyConfiguration.getAuthenticationProviders().iterator();
                            while (!authenticated.get() && authProviders.hasNext()) {
                                AuthenticationProviderResource authProvider = executionContext.getComponent(ResourceManager.class).getResource(
                                        authProviders.next(), AuthenticationProviderResource.class);

                                if (authProvider == null) {
                                    continue;
                                }

                                authProvider.authenticate(username, password, new Handler<Authentication>() {
                                    @Override
                                    public void handle(Authentication authentication) {
                                        // We succeed to authenticate the user
                                        if (authentication != null) {
                                            executionContext.setAttribute(ExecutionContext.ATTR_USER, authentication.getUsername());
                                            request.metrics().setUser(authentication.getUsername());
                                            authenticated.set(true);
                                        }
                                    }
                                });
                            }

                            if (authenticated.get()) {
                                if (buffer.length() > 0) {
                                    super.write(buffer);
                                }

                                super.end();
                            } else {
                                sendError(policyChain, username);
                            }
                        } else {
                            sendError(policyChain, null);
                        }
                    } catch (Exception ex) {
                        sendError(policyChain, null);
                    }
                } else {
                    sendError(policyChain, null);
                }
            }
        };
    }

    private void sendError(PolicyChain policyChain, String username) {
        policyChain.streamFailWith(PolicyResult.failure(
                WSSECURITY_AUTH_UNAUTHORIZED,
                HttpStatusCode.UNAUTHORIZED_401,
                "Unauthorized", Maps.<String, Object>builder()
                        .put(USERNAME_VARIABLE, username)
                        .build()));
    }
}
