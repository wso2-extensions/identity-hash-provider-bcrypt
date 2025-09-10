/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
import org.wso2.carbon.identity.hash.provider.bcrypt.constant.BcryptConstants;
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
        int costFactor = (int) initProperties.get(BcryptConstants.COST_FACTOR_PROPERTY);
        String version = (String) initProperties.get(BcryptConstants.VERSION_PROPERTY);

        return new Object[][]{
                {costFactor, BcryptConstants.DEFAULT_COST_FACTOR},
                {version, BcryptConstants.DEFAULT_BCRYPT_VERSION}
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
            initProperties.put(BcryptConstants.COST_FACTOR_PROPERTY, costFactor);
        }
        if (version != null) {
            initProperties.put(BcryptConstants.VERSION_PROPERTY, version);
        }

        bcryptHashProvider.init(initProperties);
        Map<String, Object> bcryptParams = bcryptHashProvider.getParameters();

        if (costFactor == null) {
            Assert.assertEquals(bcryptParams.get(BcryptConstants.COST_FACTOR_PROPERTY),
                    BcryptConstants.DEFAULT_COST_FACTOR);
        } else {
            Assert.assertEquals(bcryptParams.get(BcryptConstants.COST_FACTOR_PROPERTY), Integer.parseInt(costFactor));
        }

        if (version == null) {
            Assert.assertEquals(bcryptParams.get(BcryptConstants.VERSION_PROPERTY),
                    BcryptConstants.DEFAULT_BCRYPT_VERSION);
        } else {
            Assert.assertEquals(bcryptParams.get(BcryptConstants.VERSION_PROPERTY), version);
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
        initProperties.put(BcryptConstants.COST_FACTOR_PROPERTY, String.valueOf(costFactor));
        initProperties.put(BcryptConstants.VERSION_PROPERTY, "2a");

        bcryptHashProvider.init(initProperties);
        Assert.assertEquals(bcryptHashProvider.getParameters().get(BcryptConstants.COST_FACTOR_PROPERTY), costFactor);
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
        initProperties.put(BcryptConstants.COST_FACTOR_PROPERTY, costFactor);
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
        initProperties.put(BcryptConstants.VERSION_PROPERTY, version);
        bcryptHashProvider.init(initProperties);
        Assert.assertEquals(bcryptHashProvider.getParameters().get(BcryptConstants.VERSION_PROPERTY), version);
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
        initProperties.put(BcryptConstants.VERSION_PROPERTY, version);
        bcryptHashProvider.init(initProperties);
    }

    @Test
    public void testCalculateHashAlwaysGeneratesDifferentHashes() throws HashProviderException {

        initializeHashProvider("10", "2a");
        char[] password = "testPassword123".toCharArray();

        byte[] hash1 = bcryptHashProvider.calculateHash(password, null);
        byte[] hash2 = bcryptHashProvider.calculateHash(password, null);
        byte[] hash3 = bcryptHashProvider.calculateHash(password, null);

        Assert.assertNotEquals(new String(hash1, StandardCharsets.UTF_8), new String(hash2, StandardCharsets.UTF_8));
        Assert.assertNotEquals(new String(hash1, StandardCharsets.UTF_8), new String(hash3, StandardCharsets.UTF_8));
        Assert.assertNotEquals(new String(hash2, StandardCharsets.UTF_8), new String(hash3, StandardCharsets.UTF_8));

        String hashStr1 = new String(hash1, StandardCharsets.UTF_8);
        Assert.assertEquals(hashStr1.length(), 60);
        Assert.assertEquals(new String(hash2, StandardCharsets.UTF_8).length(), 60);
        Assert.assertEquals(new String(hash3, StandardCharsets.UTF_8).length(), 60);

        Assert.assertTrue(hashStr1.startsWith("$2a$10$"));
    }

    @Test
    public void testHashValidationWorks() throws HashProviderException {

        initializeHashProvider("10", "2a");
        char[] password = "testPassword123".toCharArray();

        byte[] hash = bcryptHashProvider.calculateHash(password, "any-value-ignored");

        boolean isValid = bcryptHashProvider.validateHash(password, hash, "any-value-ignored");
        Assert.assertTrue(isValid);

        boolean isInvalid = bcryptHashProvider.validateHash
                ("wrongPassword".toCharArray(), hash, "any-value-ignored");
        Assert.assertFalse(isInvalid);
    }

    @Test
    public void testSaltParameterCompletelyIgnored() throws HashProviderException {

        initializeHashProvider("10", "2a");
        char[] password = "testPassword123".toCharArray();

        byte[] hash1 = bcryptHashProvider.calculateHash(password, null);
        byte[] hash2 = bcryptHashProvider.calculateHash(password, "");
        byte[] hash3 = bcryptHashProvider.calculateHash(password, "salt1");
        byte[] hash4 = bcryptHashProvider.calculateHash(password, "salt2");

        String hashStr1 = new String(hash1, StandardCharsets.UTF_8);
        String hashStr2 = new String(hash2, StandardCharsets.UTF_8);
        String hashStr3 = new String(hash3, StandardCharsets.UTF_8);
        String hashStr4 = new String(hash4, StandardCharsets.UTF_8);

        Assert.assertNotEquals(hashStr1, hashStr2);
        Assert.assertNotEquals(hashStr1, hashStr3);
        Assert.assertNotEquals(hashStr1, hashStr4);
        Assert.assertNotEquals(hashStr2, hashStr3);
        Assert.assertNotEquals(hashStr2, hashStr4);
        Assert.assertNotEquals(hashStr3, hashStr4);
    }

    @Test
    public void testValidateHashWithDifferentSaltParameters() throws HashProviderException {

        initializeHashProvider("10", "2a");
        char[] password = "testPassword123".toCharArray();

        byte[] hash = bcryptHashProvider.calculateHash(password, "initial-salt");

        boolean isValid1 = bcryptHashProvider.validateHash(password, hash, null);
        boolean isValid2 = bcryptHashProvider.validateHash(password, hash, "");
        boolean isValid3 = bcryptHashProvider.validateHash(password, hash, "different-salt");
        boolean isValid4 = bcryptHashProvider.validateHash(password, hash, "original-salt");

        Assert.assertTrue(isValid1);
        Assert.assertTrue(isValid2);
        Assert.assertTrue(isValid3);
        Assert.assertTrue(isValid4);

        boolean isInvalid = bcryptHashProvider.validateHash("wrong".toCharArray(), hash, "any-salt");
        Assert.assertFalse(isInvalid);
    }

    @Test
    public void testSupportsValidateHash() {

        Assert.assertTrue(bcryptHashProvider.supportsValidateHash());
    }

    @Test
    public void testGetAlgorithm() {

        Assert.assertEquals(bcryptHashProvider.getAlgorithm(), BcryptConstants.BCRYPT_HASHING_ALGORITHM);
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

    @Test
    public void testVeryShortPassword() throws HashProviderException {

        initializeHashProvider("10", "2a");
        char[] shortPassword = "a".toCharArray();

        byte[] hash = bcryptHashProvider.calculateHash(shortPassword, null);
        Assert.assertNotNull(hash);

        boolean isValid = bcryptHashProvider.validateHash(shortPassword, hash, null);
        Assert.assertTrue(isValid);
    }

    @Test
    public void testSpecialCharacterPassword() throws HashProviderException {

        initializeHashProvider("10", "2a");
        char[] specialPassword = "p@ssw0rd!$%^&*()".toCharArray();

        byte[] hash = bcryptHashProvider.calculateHash(specialPassword, null);
        Assert.assertNotNull(hash);

        boolean isValid = bcryptHashProvider.validateHash(specialPassword, hash, null);
        Assert.assertTrue(isValid);
    }

    @Test
    public void testUnicodePassword() throws HashProviderException {

        initializeHashProvider("10", "2a");
        char[] unicodePassword = "pässwörd中文".toCharArray();

        byte[] hash = bcryptHashProvider.calculateHash(unicodePassword, null);
        Assert.assertNotNull(hash);

        boolean isValid = bcryptHashProvider.validateHash(unicodePassword, hash, null);
        Assert.assertTrue(isValid);
    }

    @Test
    public void testMultipleHashValidations() throws HashProviderException {

        initializeHashProvider("10", "2a");
        char[] password = "testPassword123".toCharArray();

        byte[] hash1 = bcryptHashProvider.calculateHash(password, null);
        byte[] hash2 = bcryptHashProvider.calculateHash(password, "salt1");
        byte[] hash3 = bcryptHashProvider.calculateHash(password, "salt2");

        Assert.assertTrue(bcryptHashProvider.validateHash(password, hash1, null));
        Assert.assertTrue(bcryptHashProvider.validateHash(password, hash2, "any-salt"));
        Assert.assertTrue(bcryptHashProvider.validateHash(password, hash3, "different-salt"));

        Assert.assertFalse(bcryptHashProvider.validateHash("wrong".toCharArray(), hash1, null));
        Assert.assertFalse(bcryptHashProvider.validateHash("wrong".toCharArray(), hash2, "any-salt"));
        Assert.assertFalse(bcryptHashProvider.validateHash("wrong".toCharArray(), hash3, "different-salt"));
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
            initProperties.put(BcryptConstants.COST_FACTOR_PROPERTY, costFactor);
        }
        if (version != null) {
            initProperties.put(BcryptConstants.VERSION_PROPERTY, version);
        }
        bcryptHashProvider.init(initProperties);
    }
}

