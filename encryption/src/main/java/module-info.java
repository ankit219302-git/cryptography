module cryptography.encryption {
    requires org.apache.commons.codec;
    requires org.apache.commons.lang3;
    exports com.cybsec.cryptography.encryption to cryptography.client;
    exports com.cybsec.cryptography.encryption.impl to cryptography.client;
}