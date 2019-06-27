import com.mongodb.AutoEncryptionSettings;
import com.mongodb.ClientEncryptionSettings;
import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClients;
import com.mongodb.client.model.vault.DataKeyOptions;
import com.mongodb.client.vault.ClientEncryptions;
import org.bson.BsonDocument;
import org.bson.Document;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

public class ClientSideEncryptionSimpleTest {

    public static void main(String[] args) {

        // This would have to be the same master key as was used to create the encryption key
        var localMasterKey = new byte[96];
        new SecureRandom().nextBytes( localMasterKey );

        var kmsProviders = Map.of( "local", Map.<String, Object>of( "key", localMasterKey ) );
        var keyVaultNamespace = "admin.datakeys";
        var clientEncryptionSettings = ClientEncryptionSettings.builder()
                .keyVaultMongoClientSettings(MongoClientSettings.builder()
                        .applyConnectionString(new ConnectionString("mongodb://localhost"))
                        .build())
                .keyVaultNamespace(keyVaultNamespace)
                .kmsProviders(kmsProviders)
                .build();

        var clientEncryption = ClientEncryptions.create(clientEncryptionSettings);
        var dataKeyId = clientEncryption.createDataKey("local", new DataKeyOptions());
        var base64DataKeyId = Base64.getEncoder().encodeToString(dataKeyId.getData());

        var dbName = "test";
        var collName = "coll";
        var autoEncryptionSettings = AutoEncryptionSettings.builder()
                .keyVaultNamespace(keyVaultNamespace)
                .kmsProviders(kmsProviders)
                .schemaMap(Map.of(dbName + "." + collName,
                        // Need a schema that references the new data key
                        BsonDocument.parse("{" +
                                "  properties: {" +
                                "    encryptedField: {" +
                                "      encrypt: {" +
                                "        keyId: [{" +
                                "          \"$binary\": {" +
                                "            \"base64\": \"" + base64DataKeyId + "\"," +
                                "            \"subType\": \"04\"" +
                                "          }" +
                                "        }]," +
                                "        bsonType: \"string\"," +
                                "        algorithm: \"AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic\"" +
                                "      }" +
                                "    }" +
                                "  }," +
                                "  \"bsonType\": \"object\"" +
                                "}"))
                ).build();

        var clientSettings = MongoClientSettings.builder()
                .autoEncryptionSettings( autoEncryptionSettings )
                .build();

        var client = MongoClients.create( clientSettings );
        var collection = client.getDatabase( "test" ).getCollection( "coll" );
        collection.drop(); // Clear old data

        collection.insertOne( new Document( "encryptedField", "123456789" ) );

        System.out.println( collection.find().first().toJson() );
    }
}