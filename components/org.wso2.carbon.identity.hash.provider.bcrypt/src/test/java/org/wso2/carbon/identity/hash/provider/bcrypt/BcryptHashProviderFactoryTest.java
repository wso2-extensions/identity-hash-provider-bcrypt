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
        metaPropertiesExpected.add(Constants.VERSION_PROPERTY);
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
        Assert.assertEquals(bcryptParamsMap.get(Constants.VERSION_PROPERTY), Constants.DEFAULT_BCRYPT_VERSION);
    }

    @DataProvider(name = "getHashProviderWithParams")
    public Object[][] getHashProviderWithParams() {
        return new Object[][]{
                {"10", "2a"},
                {"12", "2b"},
                {"8", "2y"},
                {"15", "2a"}
        };
    }

    @Test(dataProvider = "getHashProviderWithParams")
    public void testGetHashProviderWithParams(String costFactor, String version) throws HashProviderException {
        Map<String, Object> bcryptParams = new HashMap<>();
        bcryptParams.put(Constants.COST_FACTOR_PROPERTY, costFactor);
        bcryptParams.put(Constants.VERSION_PROPERTY, version);

        bcryptHashProvider = bcryptHashProviderFactory.getHashProvider(bcryptParams);

        Assert.assertEquals(bcryptHashProvider.getParameters().get(Constants.COST_FACTOR_PROPERTY),
                Integer.parseInt(costFactor));
        Assert.assertEquals(bcryptHashProvider.getParameters().get(Constants.VERSION_PROPERTY), version);
    }

    @DataProvider(name = "getHashProviderWithPartialParams")
    public Object[][] getHashProviderWithPartialParams() {
        return new Object[][]{
                {"10", null, Constants.DEFAULT_BCRYPT_VERSION},
                {null, "2b", Constants.DEFAULT_COST_FACTOR},
                {null, null, Constants.DEFAULT_COST_FACTOR} // Both null should use defaults
        };
    }

    @Test(dataProvider = "getHashProviderWithPartialParams")
    public void testGetHashProviderWithPartialParams(String costFactor, String version, Object expectedDefault)
            throws HashProviderException {
        Map<String, Object> bcryptParams = new HashMap<>();

        if (costFactor != null) {
            bcryptParams.put(Constants.COST_FACTOR_PROPERTY, costFactor);
        }
        if (version != null) {
            bcryptParams.put(Constants.VERSION_PROPERTY, version);
        }

        bcryptHashProvider = bcryptHashProviderFactory.getHashProvider(bcryptParams);
        Map<String, Object> actualParams = bcryptHashProvider.getParameters();

        if (costFactor == null) {
            Assert.assertEquals(actualParams.get(Constants.COST_FACTOR_PROPERTY), expectedDefault);
        } else {
            Assert.assertEquals(actualParams.get(Constants.COST_FACTOR_PROPERTY), Integer.parseInt(costFactor));
        }

        if (version == null) {
            Assert.assertEquals(actualParams.get(Constants.VERSION_PROPERTY),
                    costFactor == null ? Constants.DEFAULT_BCRYPT_VERSION : Constants.DEFAULT_BCRYPT_VERSION);
        } else {
            Assert.assertEquals(actualParams.get(Constants.VERSION_PROPERTY), version);
        }
    }

    @Test
    public void testGetHashProviderWithEmptyParams() throws HashProviderException {
        Map<String, Object> emptyParams = new HashMap<>();
        bcryptHashProvider = bcryptHashProviderFactory.getHashProvider(emptyParams);

        Map<String, Object> actualParams = bcryptHashProvider.getParameters();
        Assert.assertEquals(actualParams.get(Constants.COST_FACTOR_PROPERTY), Constants.DEFAULT_COST_FACTOR);
        Assert.assertEquals(actualParams.get(Constants.VERSION_PROPERTY), Constants.DEFAULT_BCRYPT_VERSION);
    }

    @Test
    public void testGetHashProviderWithNullParams() throws HashProviderException {
        bcryptHashProvider = bcryptHashProviderFactory.getHashProvider(null);

        Map<String, Object> actualParams = bcryptHashProvider.getParameters();
        Assert.assertEquals(actualParams.get(Constants.COST_FACTOR_PROPERTY), Constants.DEFAULT_COST_FACTOR);
        Assert.assertEquals(actualParams.get(Constants.VERSION_PROPERTY), Constants.DEFAULT_BCRYPT_VERSION);
    }

    @DataProvider(name = "invalidParams")
    public Object[][] invalidParams() {
        return new Object[][]{
                {"3", "2a"},
                {"32", "2a"},
                {"abc", "2a"},
                {"10", "2x"},
                {"10", "3a"},
                {"10", "invalid"}
        };
    }

    @Test(dataProvider = "invalidParams", expectedExceptions = HashProviderException.class)
    public void testGetHashProviderWithInvalidParams(String costFactor, String version) throws HashProviderException {
        Map<String, Object> invalidParams = new HashMap<>();
        invalidParams.put(Constants.COST_FACTOR_PROPERTY, costFactor);
        invalidParams.put(Constants.VERSION_PROPERTY, version);

        bcryptHashProviderFactory.getHashProvider(invalidParams);
    }

    @Test
    public void testMultipleProviderInstances() throws HashProviderException {
        HashProvider provider1 = bcryptHashProviderFactory.getHashProvider();
        HashProvider provider2 = bcryptHashProviderFactory.getHashProvider();

        Assert.assertNotSame(provider1, provider2, "Factory should create different instances");

        Assert.assertEquals(provider1.getParameters(), provider2.getParameters());
        Assert.assertEquals(provider1.getAlgorithm(), provider2.getAlgorithm());
    }

    @Test
    public void testProviderInstancesWithDifferentConfigs() throws HashProviderException {
        Map<String, Object> params1 = new HashMap<>();
        params1.put(Constants.COST_FACTOR_PROPERTY, "8");
        params1.put(Constants.VERSION_PROPERTY, "2a");

        Map<String, Object> params2 = new HashMap<>();
        params2.put(Constants.COST_FACTOR_PROPERTY, "12");
        params2.put(Constants.VERSION_PROPERTY, "2b");

        HashProvider provider1 = bcryptHashProviderFactory.getHashProvider(params1);
        HashProvider provider2 = bcryptHashProviderFactory.getHashProvider(params2);

        Assert.assertNotEquals(provider1.getParameters(), provider2.getParameters());
        Assert.assertEquals(provider1.getParameters().get(Constants.COST_FACTOR_PROPERTY), 8);
        Assert.assertEquals(provider2.getParameters().get(Constants.COST_FACTOR_PROPERTY), 12);
        Assert.assertEquals(provider1.getParameters().get(Constants.VERSION_PROPERTY), "2a");
        Assert.assertEquals(provider2.getParameters().get(Constants.VERSION_PROPERTY), "2b");
    }

    @Test
    public void testFactoryConsistency() {
        String algorithm1 = bcryptHashProviderFactory.getAlgorithm();
        String algorithm2 = bcryptHashProviderFactory.getAlgorithm();
        Assert.assertEquals(algorithm1, algorithm2);

        Set<String> configProps1 = bcryptHashProviderFactory.getHashProviderConfigProperties();
        Set<String> configProps2 = bcryptHashProviderFactory.getHashProviderConfigProperties();
        Assert.assertEquals(configProps1, configProps2);
    }

    @Test
    public void testCreatedProviderFunctionality() throws HashProviderException {
        HashProvider provider = bcryptHashProviderFactory.getHashProvider();

        Assert.assertTrue(provider.supportsValidateHash());
        Assert.assertEquals(provider.getAlgorithm(), Constants.BCRYPT_HASHING_ALGORITHM);

        char[] password = "testPassword123".toCharArray();
        byte[] hash = provider.calculateHash(password, null);

        Assert.assertNotNull(hash);
        Assert.assertTrue(hash.length > 0);

        boolean isValid = provider.validateHash(password, hash, null);
        Assert.assertTrue(isValid);

        char[] wrongPassword = "wrongPassword".toCharArray();
        boolean isInvalid = provider.validateHash(wrongPassword, hash, null);
        Assert.assertFalse(isInvalid);
    }
}

