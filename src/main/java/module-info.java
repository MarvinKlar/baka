module link.biosmarcel.baka {
    requires javafx.controls;
    requires org.eclipse.store.storage.embedded;
    requires org.apache.commons.csv;
    requires org.eclipse.store.storage.embedded.configuration;
    requires org.jspecify;
    requires org.cryptomator.cryptolib;
    requires org.cryptomator.cryptofs;
    requires jdk.crypto.ec;

    exports link.biosmarcel.baka;
    exports link.biosmarcel.baka.bankimport;
    exports link.biosmarcel.baka.data;
    exports link.biosmarcel.baka.view;
}