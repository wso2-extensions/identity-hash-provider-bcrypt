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
import org.wso2.carbon.user.core.exceptions.HashProviderClientException;
import org.wso2.carbon.user.core.exceptions.HashProviderException;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Test class for BcryptHashProvider.
 */
public class BcryptHashProviderTest {

    private static BcryptHashProvider bcryptHashProvider = null;
    private static Map<String, Object> initProperties;

    @BeforeClass
    public void initialize() {
        bcryptHashProvider = new BcryptHashProvider();
    }

    @DataProvider(name = "initConfig")
    public Object[][] initConfig() {
        bcryptHashProvider.init();
        initProperties = bcryptHashProvider.getParameters();
        int costFactor = (int) initProperties.get(Constants.COST_FACTOR_PROPERTY);
        String version = (String) initProperties.get(Constants.VERSION_PROPERTY);

        return new Object[][]{
                {costFactor, Constants.DEFAULT_COST_FACTOR},
                {version, Constants.DEFAULT_BCRYPT_VERSION}
        };
    }

    @Test(dataProvider = "initConfig")
    public void testInitConfig(Object parameters, Object expectedValue) {
        Assert.assertEquals(parameters, expectedValue);
    }

    @DataProvider(name = "initConfigParams")
    public Object[][] initConfigParams() {
        return new Object[][]{
                {"10", "2a"},
                {"12", "2b"},
                {"8", "2y"},
                {null, "2a"},
                {"10", null}
        };
    }

    @Test(dataProvider = "initConfigParams")
    public void testInitConfigParams(String costFactor, String version) throws HashProviderException {
        Map<String, Object> initProperties = new HashMap<>();

        if (costFactor != null) {
            initProperties.put(Constants.COST_FACTOR_PROPERTY, costFactor);
        }
        if (version != null) {
            initProperties.put(Constants.VERSION_PROPERTY, version);
        }

        bcryptHashProvider.init(initProperties);
        Map<String, Object> bcryptParams = bcryptHashProvider.getParameters();

        if (costFactor == null) {
            Assert.assertEquals(bcryptParams.get(Constants.COST_FACTOR_PROPERTY), Constants.DEFAULT_COST_FACTOR);
        } else {
            Assert.assertEquals(bcryptParams.get(Constants.COST_FACTOR_PROPERTY), Integer.parseInt(costFactor));
        }

        if (version == null) {
            Assert.assertEquals(bcryptParams.get(Constants.VERSION_PROPERTY), Constants.DEFAULT_BCRYPT_VERSION);
        } else {
            Assert.assertEquals(bcryptParams.get(Constants.VERSION_PROPERTY), version);
        }
    }

    @DataProvider(name = "validCostFactors")
    public Object[][] validCostFactors() {
        return new Object[][]{
                {4}, {8}, {10}, {12}, {15}, {31}
        };
    }

    @Test(dataProvider = "validCostFactors")
    public void testValidCostFactors(int costFactor) throws HashProviderException {
        Map<String, Object> initProperties = new HashMap<>();
        initProperties.put(Constants.COST_FACTOR_PROPERTY, String.valueOf(costFactor));
        initProperties.put(Constants.VERSION_PROPERTY, "2a");

        bcryptHashProvider.init(initProperties);
        Assert.assertEquals(bcryptHashProvider.getParameters().get(Constants.COST_FACTOR_PROPERTY), costFactor);
    }

    @DataProvider(name = "invalidCostFactors")
    public Object[][] invalidCostFactors() {
        return new Object[][]{
                {"3"}, {"32"}, {"abc"}, {"-1"}, {"100"}
        };
    }

    @Test(dataProvider = "invalidCostFactors", expectedExceptions = HashProviderClientException.class)
    public void testInvalidCostFactors(String costFactor) throws HashProviderException {
        Map<String, Object> initProperties = new HashMap<>();
        initProperties.put(Constants.COST_FACTOR_PROPERTY, costFactor);
        bcryptHashProvider.init(initProperties);
    }

    @DataProvider(name = "validVersions")
    public Object[][] validVersions() {
        return new Object[][]{
                {"2a"}, {"2b"}, {"2y"}
        };
    }

    @Test(dataProvider = "validVersions")
    public void testValidVersions(String version) throws HashProviderException {
        Map<String, Object> initProperties = new HashMap<>();
        initProperties.put(Constants.VERSION_PROPERTY, version);
        bcryptHashProvider.init(initProperties);
        Assert.assertEquals(bcryptHashProvider.getParameters().get(Constants.VERSION_PROPERTY), version);
    }

    @DataProvider(name = "invalidVersions")
    public Object[][] invalidVersions() {
        return new Object[][]{
                {"2x"}, {"3a"}, {"1a"}, {"invalid"}, {""}
        };
    }

    @Test(dataProvider = "invalidVersions", expectedExceptions = HashProviderClientException.class)
    public void testInvalidVersions(String version) throws HashProviderException {
        Map<String, Object> initProperties = new HashMap<>();
        initProperties.put(Constants.VERSION_PROPERTY, version);
        bcryptHashProvider.init(initProperties);
    }

    @Test
    public void testGenerateSalt() throws HashProviderException {
        initializeHashProvider("10", "2a");
        String salt1 = bcryptHashProvider.generateSalt();
        String salt2 = bcryptHashProvider.generateSalt();

        Assert.assertNotEquals(salt1, salt2);
        Assert.assertNotNull(salt1);
        Assert.assertTrue(salt1.length() > 0);
    }

    @Test
    public void testCalculateHashWithGeneratedSalt() throws HashProviderException {
        initializeHashProvider("10", "2a");
        char[] password = "testPassword123".toCharArray();

        byte[] hash1 = bcryptHashProvider.calculateHash(password, null);
        byte[] hash2 = bcryptHashProvider.calculateHash(password, null);

        Assert.assertNotEquals(new String(hash1, StandardCharsets.UTF_8),
                new String(hash2, StandardCharsets.UTF_8));

        Assert.assertEquals(new String(hash1, StandardCharsets.UTF_8).length(), 60);
        Assert.assertEquals(new String(hash2, StandardCharsets.UTF_8).length(), 60);
    }

    @Test
    public void testCalculateHashWithProvidedSalt() throws HashProviderException {
        initializeHashProvider("10", "2a");
        char[] password = "testPassword123".toCharArray();
        String salt = bcryptHashProvider.generateSalt();

        byte[] hash1 = bcryptHashProvider.calculateHash(password, salt);
        byte[] hash2 = bcryptHashProvider.calculateHash(password, salt);

        Assert.assertEquals(new String(hash1, StandardCharsets.UTF_8),
                new String(hash2, StandardCharsets.UTF_8));
    }

    @DataProvider(name = "hashValidationScenarios")
    public Object[][] hashValidationScenarios() throws HashProviderException {
        initializeHashProvider("10", "2a");

        char[] password1 = "testPassword123".toCharArray();
        char[] password2 = "differentPassword456".toCharArray();
        String salt = bcryptHashProvider.generateSalt();

        byte[] hash1 = bcryptHashProvider.calculateHash(password1, salt);
        byte[] hash2 = bcryptHashProvider.calculateHash(password2, salt);

        return new Object[][]{
                {password1, hash1, salt, true},
                {password2, hash1, salt, false},
                {password1, hash2, salt, false},
                {"".toCharArray(), hash1, salt, false},
                {null, hash1, salt, false},
                {password1, null, salt, false},
                {password1, "invalid".getBytes(StandardCharsets.UTF_8), salt, false} // Invalid hash
        };
    }

    @Test(dataProvider = "hashValidationScenarios")
    public void testValidateHash(char[] plainText, byte[] hashedPassword, String salt, boolean expected)
            throws HashProviderException {
        initializeHashProvider("10", "2a");
        boolean result = bcryptHashProvider.validateHash(plainText, hashedPassword, salt);
        Assert.assertEquals(result, expected);
    }

    @Test
    public void testSupportsValidateHash() {
        Assert.assertTrue(bcryptHashProvider.supportsValidateHash());
    }

    @DataProvider(name = "hashProviderErrorScenarios")
    public Object[][] hashProviderErrorScenarios() {
        return new Object[][]{
                {"".toCharArray(), bcryptHashProvider.generateSalt(), "10", "2a",
                        ErrorMessage.ERROR_CODE_EMPTY_VALUE.getCode()},
                {null, bcryptHashProvider.generateSalt(), "10", "2a",
                        ErrorMessage.ERROR_CODE_EMPTY_VALUE.getCode()},
                {"password".toCharArray(), "", "10", "2a",
                        ErrorMessage.ERROR_CODE_INVALID_SALT_FORMAT.getCode()},
                {"password".toCharArray(), "invalidSalt", "10", "2a",
                        ErrorMessage.ERROR_CODE_INVALID_SALT_FORMAT.getCode()},
                {"password".toCharArray(), null, "10", "2a",
                        ErrorMessage.ERROR_CODE_INVALID_SALT_FORMAT.getCode()},
        };
    }

    @Test
    public void testGetAlgorithm() {
        Assert.assertEquals(bcryptHashProvider.getAlgorithm(), Constants.BCRYPT_HASHING_ALGORITHM);
    }

    @Test
    public void testGetUtf8ByteLength() throws HashProviderException {
        initializeHashProvider("10", "2a");

        char[] asciiChars = "hello".toCharArray();
        Assert.assertEquals(bcryptHashProvider.getUtf8ByteLength(asciiChars), 5);
        char[] utf8Chars = "héllo".toCharArray();
        Assert.assertEquals(bcryptHashProvider.getUtf8ByteLength(utf8Chars), 6);
        Assert.assertEquals(bcryptHashProvider.getUtf8ByteLength(null), 0);
        Assert.assertEquals(bcryptHashProvider.getUtf8ByteLength(new char[0]), 0);
    }

    @Test
    public void testLongPasswordHandling() throws HashProviderException {
        initializeHashProvider("4", "2a");

        StringBuilder longPasswordBuilder = new StringBuilder();
        for (int i = 0; i < 80; i++) {
            longPasswordBuilder.append("a");
        }
        char[] longPassword = longPasswordBuilder.toString().toCharArray();

        try {
            bcryptHashProvider.calculateHash(longPassword, null);
        } catch (HashProviderClientException e) {
            Assert.assertTrue(e.getErrorCode().contains(ErrorMessage.ERROR_CODE_PLAIN_TEXT_TOO_LONG.getCode()));
        }
    }

    /**
     * Initializing the HashProvider with given meta properties.
     *
     * @param costFactor The cost factor.
     * @param version    The BCrypt version.
     */
    private void initializeHashProvider(String costFactor, String version) throws HashProviderException {
        initProperties = new HashMap<>();
        if (costFactor != null) {
            initProperties.put(Constants.COST_FACTOR_PROPERTY, costFactor);
        }
        if (version != null) {
            initProperties.put(Constants.VERSION_PROPERTY, version);
        }
        bcryptHashProvider.init(initProperties);
    }
}

