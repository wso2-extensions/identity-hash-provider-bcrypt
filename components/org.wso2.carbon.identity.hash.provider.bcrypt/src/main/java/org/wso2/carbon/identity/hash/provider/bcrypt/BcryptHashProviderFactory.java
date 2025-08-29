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

package org.wso2.carbon.identity.hash.provider.bcrypt;

import org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants;
import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.hash.HashProvider;
import org.wso2.carbon.user.core.hash.HashProviderFactory;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The class contains the implementation of Bcrypt HashProvider Factory.
 */
public class BcryptHashProviderFactory implements HashProviderFactory {

    @Override
    public HashProvider getHashProvider() {
        BcryptHashProvider bcryptHashProvider = new BcryptHashProvider();
        bcryptHashProvider.init();
        return bcryptHashProvider;
    }

    @Override
    public HashProvider getHashProvider(Map<String, Object> initProperties) throws HashProviderException {
        BcryptHashProvider bcryptHashProvider = new BcryptHashProvider();
        bcryptHashProvider.init(initProperties);
        return bcryptHashProvider;
    }

    @Override
    public Set<String> getHashProviderConfigProperties() {
        Set<String> metaProperties = new HashSet<>();
        metaProperties.add(Constants.COST_FACTOR_PROPERTY);
        metaProperties.add(Constants.VERSION_PROPERTY);

        return metaProperties;
    }

    @Override
    public String getAlgorithm() {
        return Constants.BCRYPT_HASHING_ALGORITHM;
    }
}
