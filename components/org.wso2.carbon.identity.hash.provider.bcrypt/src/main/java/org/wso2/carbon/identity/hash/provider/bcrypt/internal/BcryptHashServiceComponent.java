/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.hash.provider.bcrypt.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.hash.provider.bcrypt.BcryptHashProviderFactory;
import org.wso2.carbon.user.core.hash.HashProviderFactory;

/**
 * This class contains the Bcrypt hashing service component.
 */
@Component(
        name = "org.wso2.carbon.identity.hash.provider.bcrypt.component",
        immediate = true
)
public class BcryptHashServiceComponent {

    private static final Log log = LogFactory.getLog(BcryptHashServiceComponent.class);

    @Activate
    protected void activate(ComponentContext componentContext) {

        try {
            HashProviderFactory hashProviderFactory = new BcryptHashProviderFactory();
            componentContext.getBundleContext().registerService(HashProviderFactory.class.getName(),
                    hashProviderFactory, null);

            if (log.isDebugEnabled()) {
                log.debug("Bcrypt bundle activated successfully.");
            }
        } catch (Throwable e) {
            log.error("Failed to activate Bcrypt bundle", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext componentContext) {

        if (log.isDebugEnabled()) {
            log.debug("Bcrypt bundle is deactivated.");
        }
    }
}
