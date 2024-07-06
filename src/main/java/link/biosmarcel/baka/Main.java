package link.biosmarcel.baka;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TabPane;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import link.biosmarcel.baka.data.Data;
import link.biosmarcel.baka.view.AccountsView;
import link.biosmarcel.baka.view.EvaluationView;
import link.biosmarcel.baka.view.PaymentsView;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.eclipse.store.afs.nio.types.NioFileSystem;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageFoundation;
import org.eclipse.store.storage.types.Storage;
import org.eclipse.store.storage.types.StorageBackupSetup;
import org.eclipse.store.storage.types.StorageChannelCountProvider;
import org.eclipse.store.storage.types.StorageConfiguration;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.spec.KeySpec;
import java.util.Objects;

public class Main extends Application {
    private static Path getDataDir(final String... children) {
        final String[] pathElements = new String[children.length + 1];
        pathElements[0] = "baka";
        System.arraycopy(children, 0, pathElements, 1, children.length);
        return Paths.get(System.getenv("APPDATA"), pathElements);
    }

    @Override
    public void start(Stage stage) {
        stage.setTitle("Baka");
        stage.getIcons().add(new Image(getClass().getResourceAsStream("icon.png")));

        // FIXME This seems dumb?
        Platform.setImplicitExit(true);

        final TabPane tabs = new TabPane();
        final Scene scene = new Scene(tabs, 800, 600);
        scene.getStylesheets().add(Objects.requireNonNull(Main.class.getResource("base.css")).toExternalForm());
        stage.setScene(scene);

        stage.sizeToScene();
        stage.show();

        PasswordField passwordField = new PasswordField();
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.initOwner(stage);
        alert.getDialogPane().setContent(passwordField);
        alert.setTitle(stage.getTitle() + " - Vault Access");
        alert.setHeaderText("Please insert your master password to encrypt the data:");
        final var choice = alert.showAndWait();

        if (!(choice.isPresent() && choice.get().equals(ButtonType.OK))) {
            Platform.exit();
            return;
        }

        try {
            Files.createDirectories(getDataDir("vault"));

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(passwordField.getText().toCharArray(),
                    "2394ec46e279b2a6c9b7a6ec634ed4738866e6f4".getBytes(), 65536, 512);
            SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

            try (
                    Masterkey masterkey = new Masterkey(key.getEncoded());
            ) {
                MasterkeyLoader loader =
                        ignoredUri -> masterkey.copy(); //create a copy because the key handed over to init() method will be destroyed
                CryptoFileSystemProperties
                        fsProps = CryptoFileSystemProperties.cryptoFileSystemProperties().withKeyLoader(loader).build();

                if (!Files.exists(getDataDir("vault", "vault.cryptomator"))) {
                    CryptoFileSystemProvider.initialize(getDataDir("vault"), fsProps, URI.create("baka"));
                }

                final var data = new Data();
                final var cryptoFS = CryptoFileSystemProvider.newFileSystem(getDataDir("vault"), fsProps);
                final var nioFS = NioFileSystem.New(cryptoFS);
                final var storageManager = EmbeddedStorageFoundation.New()
                        .setConfiguration(
                                StorageConfiguration.Builder()
                                        .setStorageFileProvider(
                                                Storage.FileProviderBuilder(nioFS)
                                                        .setDirectory(nioFS.ensureDirectoryPath("/storageDir"))
                                                        .createFileProvider()
                                        )
                                        .setChannelCountProvider(
                                                StorageChannelCountProvider.New(1)) // Limited to 1 for CryptoFS
                                        .setBackupSetup(StorageBackupSetup.New(
                                                nioFS.ensureDirectoryPath("/backupDir")
                                        ))
                                        .createConfiguration()
                        )
                        .setRoot(data)
                        .createEmbeddedStorageManager()
                        .start();

                final ApplicationState state =
                        new ApplicationState(storageManager, storageManager.createEagerStorer(), data);
                tabs.getTabs().addAll(
                        new PaymentsView(state),
                        new AccountsView(state),
                        new EvaluationView(state)
                );
                tabs.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);

                stage.setOnCloseRequest((ae) -> {
                    try {
                        cryptoFS.close();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    Platform.exit();
                    System.exit(0);
                });

            }
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] __) {
        launch();
    }
}