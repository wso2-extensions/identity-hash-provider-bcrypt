/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants;
import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.hash.HashProvider;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Test class for BcryptHashProviderFactory.
 */
public class BcryptHashProviderFactoryTest {

    private static BcryptHashProviderFactory bcryptHashProviderFactory = null;
    private static HashProvider bcryptHashProvider = null;

    @BeforeClass
    public void initialize() {

        bcryptHashProviderFactory = new BcryptHashProviderFactory();
    }

    @Test
    public void testGetConfigProperties() {

        Set<String> metaPropertiesActual = bcryptHashProviderFactory.getHashProviderConfigProperties();
        Set<String> metaPropertiesExpected = new HashSet<>();
        metaPropertiesExpected.add(Constants.COST_FACTOR_PROPERTY);
        Assert.assertEquals(metaPropertiesActual, metaPropertiesExpected);
    }

    @Test
    public void testGetAlgorithm() {

        Assert.assertEquals(bcryptHashProviderFactory.getAlgorithm(), Constants.BCRYPT_HASHING_ALGORITHM);
    }

    @Test
    public void testGetHashProviderWithDefaultParams() {

        bcryptHashProvider = bcryptHashProviderFactory.getHashProvider();
        Map<String, Object> bcryptParamsMap = bcryptHashProvider.getParameters();
        Assert.assertEquals(bcryptParamsMap.get(Constants.COST_FACTOR_PROPERTY), Constants.DEFAULT_COST_FACTOR);
    }

    @DataProvider(name = "getHashProviderWithParams")
    public Object[][] getHashProviderWithParams() {

        return new Object[][]{
                {"10"},
                {"12"},
                {"14"}
        };
    }

    @Test(dataProvider = "getHashProviderWithParams")
    public void testGetHashProviderWithParams(String costFactor)
            throws HashProviderException {

        Map<String, Object> bcryptParams = new HashMap<>();
        bcryptParams.put(Constants.COST_FACTOR_PROPERTY, costFactor);
        bcryptHashProvider = bcryptHashProviderFactory.getHashProvider(bcryptParams);
        Assert.assertEquals(bcryptHashProvider.getParameters().get(Constants.COST_FACTOR_PROPERTY),
                Integer.parseInt(costFactor));
    }
}
