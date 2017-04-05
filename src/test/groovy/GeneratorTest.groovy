import com.mulesoft.qa.automation.certificates.KeyUtils
import com.mulesoft.qa.automation.certificates.model.CertificatesBundle
import org.testng.annotations.Test


/**
 * Created by naitse on 3/2/17.
 */
class GeneratorTest {

    @Test
    void bcGenerator(){

        CertificatesBundle certificatesBundle = KeyUtils.generateCertificateBundle()

        System.out.println(certificatesBundle.signedEntities.first().signedPrivateKeyString)
        System.out.println(certificatesBundle.signedEntities.first().signedCertString)


    }
}
