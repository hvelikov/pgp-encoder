package bg.bo.way4mi;

import au.com.safenet.crypto.provider.RSAPubKey;
import au.com.safenet.crypto.provider.SAFENETProvider;
import org.apache.camel.Exchange;
import org.apache.camel.PropertyInject;
//
// import org.apache.camel.converter.stream.OutputStreamBuilder;
import org.apache.camel.spi.DataFormat;
import org.apache.camel.spi.DataFormatName;
//import org.apache.camel.support.ServiceSupport;
//import org.apache.camel.util.ExchangeHelper;
import org.apache.camel.support.ExchangeHelper;
import org.apache.camel.support.builder.OutputStreamBuilder;
import org.apache.camel.support.service.ServiceSupport;
import org.apache.camel.util.IOHelper;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Date;

public class CryptoDataFormat extends ServiceSupport implements DataFormat, DataFormatName {
    //slot, kPriv, password, has to be set accordingly
    @PropertyInject("ufx.key.slot")
    private int slot;

    @PropertyInject("ufx.key.alas")
    private String alias;

    @PropertyInject("ufx.key.pub")
    private String pubkey;

    @PropertyInject("ufx.key.pwd")
    private String password;

//    @PropertyInject(value = "ufx.key.usehsm", defaultValue = "True")
//    private Boolean isHsm;


    private Provider safenetProvider;

    private static int BUFFER_SIZE = 1 << 16; //16*1024;

    @Override
    public void marshal(Exchange exchange, Object graph, OutputStream outputStream) throws Exception {
        //       if(isHsm)
        safenetProvider = new SAFENETProvider(slot);

        KeyStore keyStore = KeyStore.getInstance("CRYPTOKI", safenetProvider);
        keyStore.load(null, password.toCharArray());
        RSAPubKey publicKey = (RSAPubKey) keyStore.getKey(pubkey, password.toCharArray());
        PGPPublicKey pub = new JcaPGPKeyConverter().getPGPPublicKey(1, publicKey, new Date());
        int sessionAlgorithm = PGPEncryptedData.AES_256;
        PGPEncryptedDataGenerator edg = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(sessionAlgorithm).setWithIntegrityPacket(true).setProvider(new BouncyCastleProvider()));
        edg.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pub).setProvider(new BouncyCastleProvider()));
        ArmoredOutputStream out = new ArmoredOutputStream(outputStream);
        OutputStream cOut = edg.open(out, new byte[1 << 16]);
        PGPCompressedDataGenerator comDG = new PGPCompressedDataGenerator(PGPCompressedData.BZIP2);

        String fileName = exchange.getIn().getHeader(Exchange.FILE_NAME, String.class); //exchange.getIn().getHeader(CAMEL_FILE_NAME, String.class);
        InputStream input = ExchangeHelper.convertToMandatoryType(exchange, InputStream.class, graph);

        //PGPUtil.writeFileToLiteralData(comDG.open(cOut), PGPLiteralData.BINARY, new File(filePath) , new byte[1<<16]);
        PGPLiteralDataGenerator litData = new PGPLiteralDataGenerator();
        OutputStream litOut = litData.open(comDG.open(cOut), PGPLiteralData.BINARY, fileName + "_ZZ", new Date(), new byte[BUFFER_SIZE]);

        try {
            copyStream(input, litOut);
            //pipeFileContents(input, litOut);
        } finally {
            IOHelper.close(litOut);
            comDG.close();
            IOHelper.close(cOut, out, outputStream, input);
        }
    }

    @Override
    public Object unmarshal(Exchange exchange, InputStream stream) throws Exception {
//        if(isHsm)
        safenetProvider = new SAFENETProvider(slot);
        KeyStore keyStore = KeyStore.getInstance("CRYPTOKI", safenetProvider);
        keyStore.load(null, password.toCharArray());
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());

        InputStream inputStream = PGPUtil.getDecoderStream(stream);
        JcaKeyFingerprintCalculator calc = new JcaKeyFingerprintCalculator();
        PGPObjectFactory encryptedObjects = new PGPObjectFactory(inputStream, calc);
        PGPEncryptedDataList dataList;
        Object o = encryptedObjects.nextObject();

        if (o instanceof PGPEncryptedDataList)
            dataList = (PGPEncryptedDataList) o;
        else
            dataList = (PGPEncryptedDataList) encryptedObjects.nextObject();

        PGPPublicKeyEncryptedData pgpPublicKeyEncryptedData = (PGPPublicKeyEncryptedData) dataList.get(0);
        InputStream temp = pgpPublicKeyEncryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(safenetProvider).setContentProvider(new BouncyCastleProvider()).build(privateKey));

        JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(temp);

        o = jcaPGPObjectFactory.nextObject();

        if (o instanceof PGPCompressedData) {
            PGPCompressedData compressedData = (PGPCompressedData) o;
            jcaPGPObjectFactory = new JcaPGPObjectFactory(compressedData.getDataStream());
            o = jcaPGPObjectFactory.nextObject();
        }

        PGPLiteralData literalData = (PGPLiteralData) o;
        InputStream decryptedStream = literalData.getInputStream();
        OutputStreamBuilder osb = OutputStreamBuilder.withExchange(exchange);
        // write to tempory file
        try {
            copyStream(decryptedStream, osb);
        } finally {
            IOHelper.close(inputStream, stream, osb, temp);
        }
        return osb.build();
    }

    private void copyStream(InputStream input, OutputStream litOut) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        int bytesRead;
        while ((bytesRead = input.read(buffer)) != -1) {
            litOut.write(buffer, 0, bytesRead);
            litOut.flush();
        }
    }

    @Override
    public String getDataFormatName() {
        return "PGPHSM";
    }

    @Override
    protected void doStart() throws Exception {
//        if(isHsm)
//            safenetProvider = new SAFENETProvider(slot);
        return;
    }

    @Override
    protected void doStop() throws Exception {
        return;
    }

}
