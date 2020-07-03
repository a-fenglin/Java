import java.awt.BorderLayout;



import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.Enumeration;
import javax.crypto.Mac;
 
 

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

 
 
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.swing.JTabbedPane;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JButton;
import javax.swing.JRadioButton;
import javax.swing.border.TitledBorder;
import javax.swing.border.EtchedBorder;
import java.awt.Color;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ButtonGroup;
import javax.swing.JPasswordField;

public class GUITool extends JFrame {

	
	private JPanel contentPane;
	private JTextField textFieldString;
	private JTextField textFieldFileName;
	private JTextField textFieldMD5;
	private JTextField textFieldSHA1;
	private JTextField textFieldSHA2_224;
	private JTextField textFieldSHA2_256;
	private JTextField textFieldSHA2_384;
	private JTextField textFieldSHA2_512;
	private JTextField textFieldSHA3_224;
	private JTextField textFieldSHA3_256;
	private JTextField textFieldSHA3_384;
	private JTextField textFieldSHA3_512;
	private JTextField textFieldSM3;
	private JTextField textField_Name;
	private final ButtonGroup buttonGroup = new ButtonGroup();
	private JPasswordField passwordField;
	private JTextField textFieldFile_Name2;
	private JTextField textFieldVerified;
	private JTextField textFieldResult;
	private JTextField textFieldSignValue;
	private JTextField textFieldOpenString;
	private JTextField textFieldZUC_128;
	private JTextField textFieldZUC_256;
	private JTextField textFieldZUC_256_32;
	private JTextField textFieldZUC_256_64;
	private JTextField textFieldFileName_3;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					GUITool frame = new GUITool();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public GUITool()   {
		setTitle("GUITool");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 870, 657);
		contentPane = new JPanel();
		contentPane.setToolTipText("");
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));
		setContentPane(contentPane);
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		contentPane.add(tabbedPane, BorderLayout.CENTER);
		
		JPanel panelHashCalulator = new JPanel();
		tabbedPane.addTab("HASH值计算", null, panelHashCalulator, null);
		panelHashCalulator.setLayout(null);
		
		JLabel lblInputString = new JLabel("\u8F93\u5165\u5B57\u7B26\u4E32\uFF1A");
		lblInputString.setBounds(10, 20, 102, 15);
		panelHashCalulator.add(lblInputString);
		
		textFieldString = new JTextField();
		textFieldString.setBounds(154, 17, 458, 21);
		panelHashCalulator.add(textFieldString);
		textFieldString.setColumns(10);
		
		JLabel lblInputFile = new JLabel("\u6253\u5F00\u6587\u4EF6\u5E76\u8BA1\u7B97\uFF1A");
		lblInputFile.setBounds(10, 62, 128, 15);
		panelHashCalulator.add(lblInputFile);
		
		textFieldFileName = new JTextField();
		textFieldFileName.setBounds(154, 59, 458, 21);
		panelHashCalulator.add(textFieldFileName);
		textFieldFileName.setColumns(10);
		
		JCheckBox chckbxMD5 = new JCheckBox("MD5");
		chckbxMD5.setBounds(10, 96, 109, 23);
		panelHashCalulator.add(chckbxMD5);
		
		JCheckBox chckbxSHA1 = new JCheckBox("SHA1");
		chckbxSHA1.setBounds(10, 137, 109, 23);
		panelHashCalulator.add(chckbxSHA1);
		
		JCheckBox chckbxSHA2_224 = new JCheckBox("SHA2-224");
		chckbxSHA2_224.setBounds(10, 174, 109, 23);
		panelHashCalulator.add(chckbxSHA2_224);
		
		textFieldMD5 = new JTextField();
		textFieldMD5.setBounds(154, 101, 458, 21);
		panelHashCalulator.add(textFieldMD5);
		textFieldMD5.setColumns(10);
		
		JCheckBox chckbxSHA2_256 = new JCheckBox("SHA2-256");
		chckbxSHA2_256.setBounds(10, 216, 109, 23);
		panelHashCalulator.add(chckbxSHA2_256);
		
		textFieldSHA1 = new JTextField();
		textFieldSHA1.setBounds(154, 138, 458, 21);
		panelHashCalulator.add(textFieldSHA1);
		textFieldSHA1.setColumns(10);
		
		textFieldSHA2_224 = new JTextField();
		textFieldSHA2_224.setBounds(154, 175, 458, 21);
		panelHashCalulator.add(textFieldSHA2_224);
		textFieldSHA2_224.setColumns(10);
		
		textFieldSHA2_256 = new JTextField();
		textFieldSHA2_256.setBounds(154, 217, 458, 21);
		panelHashCalulator.add(textFieldSHA2_256);
		textFieldSHA2_256.setColumns(10);
		
		JCheckBox chckbxSHA2_384 = new JCheckBox("SHA2-384");
		chckbxSHA2_384.setBounds(10, 257, 109, 23);
		panelHashCalulator.add(chckbxSHA2_384);
		
		textFieldSHA2_384 = new JTextField();
		textFieldSHA2_384.setBounds(154, 258, 458, 21);
		panelHashCalulator.add(textFieldSHA2_384);
		textFieldSHA2_384.setColumns(10);
		
		JCheckBox chckbxSHA2_512 = new JCheckBox("SHA2-512");
		chckbxSHA2_512.setBounds(10, 300, 109, 23);
		panelHashCalulator.add(chckbxSHA2_512);
		
		JCheckBox chckbxSHA3_224 = new JCheckBox("SHA3-224");
		chckbxSHA3_224.setBounds(10, 339, 109, 23);
		panelHashCalulator.add(chckbxSHA3_224);
		
		JCheckBox chckbxSHA3_256 = new JCheckBox("SHA3-256");
		chckbxSHA3_256.setBounds(10, 379, 109, 23);
		panelHashCalulator.add(chckbxSHA3_256);
		
		textFieldSHA2_512 = new JTextField();
		textFieldSHA2_512.setBounds(154, 301, 458, 21);
		panelHashCalulator.add(textFieldSHA2_512);
		textFieldSHA2_512.setColumns(10);
		
		textFieldSHA3_224 = new JTextField();
		textFieldSHA3_224.setBounds(154, 340, 458, 21);
		panelHashCalulator.add(textFieldSHA3_224);
		textFieldSHA3_224.setColumns(10);
		
		textFieldSHA3_256 = new JTextField();
		textFieldSHA3_256.setBounds(154, 380, 458, 21);
		panelHashCalulator.add(textFieldSHA3_256);
		textFieldSHA3_256.setColumns(10);
		
		JCheckBox chckbxSHA3_384 = new JCheckBox("SHA3-384");
		chckbxSHA3_384.setBounds(10, 421, 109, 23);
		panelHashCalulator.add(chckbxSHA3_384);
		
		JCheckBox chckbxSHA3_512 = new JCheckBox("SHA3-512");
		chckbxSHA3_512.setBounds(10, 461, 109, 23);
		panelHashCalulator.add(chckbxSHA3_512);
		
		JCheckBox chckbxSM3 = new JCheckBox("SM3");
		chckbxSM3.setBounds(10, 499, 109, 23);
		panelHashCalulator.add(chckbxSM3);
		
		textFieldSHA3_384 = new JTextField();
		textFieldSHA3_384.setBounds(154, 422, 458, 21);
		panelHashCalulator.add(textFieldSHA3_384);
		textFieldSHA3_384.setColumns(10);
		
		textFieldSHA3_512 = new JTextField();
		textFieldSHA3_512.setBounds(154, 462, 458, 21);
		panelHashCalulator.add(textFieldSHA3_512);
		textFieldSHA3_512.setColumns(10);
		
		textFieldSM3 = new JTextField();
		textFieldSM3.setBounds(154, 500, 458, 21);
		panelHashCalulator.add(textFieldSM3);
		textFieldSM3.setColumns(10);
		
		JButton btnCalculateString = new JButton("\u5B57\u7B26\u4E32HASH\u8BA1\u7B97");
		btnCalculateString.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JCheckBox[] checkboxes = {chckbxMD5, chckbxSHA1, chckbxSHA2_224,chckbxSHA2_256,chckbxSHA2_384,chckbxSHA2_512,chckbxSHA3_224,chckbxSHA3_256,chckbxSHA3_384,chckbxSHA3_512,chckbxSM3};
				JTextField[] textFields = {textFieldMD5, textFieldSHA1, textFieldSHA2_224,textFieldSHA2_256,textFieldSHA2_384,textFieldSHA2_512,textFieldSHA3_224,textFieldSHA3_256,textFieldSHA3_384,textFieldSHA3_512,textFieldSM3};
				String[] hashAlgs = {"MD5", "SHA1", "SHA-224","SHA-256","SHA-384","SHA-512","SHA3-224","SHA3-256","SHA3-384","SHA3-512","SM3"};
				
				for (JTextField textField : textFields) {
					textField.setText("");
				}
				  
					String s = textFieldString.getText();
					for (int i = 0; i < checkboxes.length; i++) {
						if (checkboxes[i].isSelected()) {
							try {
								Security.addProvider(new BouncyCastleProvider());
								MessageDigest md = MessageDigest.getInstance(hashAlgs[i]);
 
 
 
								
								textFields[i].setText(Hex.toHexString(md.digest(s.getBytes())));
							} catch (NoSuchAlgorithmException e1) {
								 
								e1.printStackTrace();
							
						}
					}
				}
			}
		});
		btnCalculateString.setBounds(668, 255, 114, 83);
		panelHashCalulator.add(btnCalculateString);
		
		JButton btnClose = new JButton("\u9000\u51FA");
		btnClose.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				System.exit(0);
			}
		});
		btnClose.setBounds(710, 524, 86, 37);
		panelHashCalulator.add(btnClose);
		
		JButton btnOpenFile = new JButton("\u6587\u4EF6HASH\u8BA1\u7B97");
		btnOpenFile.addActionListener(new ActionListener() {   
			public void actionPerformed(ActionEvent arg0) {   
				
				JCheckBox[] checkboxes = {chckbxMD5, chckbxSHA1, chckbxSHA2_224,chckbxSHA2_256,chckbxSHA2_384,chckbxSHA2_512,chckbxSHA3_224,chckbxSHA3_256,chckbxSHA3_384,chckbxSHA3_512,chckbxSM3};
				JTextField[] textFields = {textFieldMD5, textFieldSHA1, textFieldSHA2_224,textFieldSHA2_256,textFieldSHA2_384,textFieldSHA2_512,textFieldSHA3_224,textFieldSHA3_256,textFieldSHA3_384,textFieldSHA3_512,textFieldSM3};
				String[] hashAlgs = {"MD5", "SHA1", "SHA-224","SHA-256","SHA-384","SHA-512","SHA3-224","SHA3-256","SHA3-384","SHA3-512","SM3"};
				
				for (JTextField textField : textFields) {
					textField.setText("");
				}
				
					JFileChooser fileChooser = new JFileChooser();              
					if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
						File file = fileChooser.getSelectedFile();
						String ss = textFieldFileName.getText();
						textFieldFileName.setText(fileChooser.getSelectedFile().getName());   
					for (int i = 0; i < checkboxes.length; i++) {   
						if (checkboxes[i].isSelected()) {
						try {
							Security.addProvider(new BouncyCastleProvider());
							MessageDigest md = MessageDigest.getInstance(hashAlgs[i]);
							try (FileInputStream fis = new FileInputStream(file);
									DigestInputStream dis = new DigestInputStream(fis, md)) {
 
								byte[] buffer = new byte[1024];
								while(dis.read(buffer) != -1);
								
								textFields[i].setText(Hex.toHexString(md.digest()));  
							}
						} catch (NoSuchAlgorithmException e) {
							 
							e.printStackTrace();
						} catch (FileNotFoundException e) {
							 
							e.printStackTrace();
						} catch (IOException e) {
							 
							e.printStackTrace();
						}
							}
						}

					}				
			}
		});
		btnOpenFile.setBounds(668, 58, 114, 83);
		panelHashCalulator.add(btnOpenFile);
		
		JPanel panelFileEncrypt_Decrypt = new JPanel();
		tabbedPane.addTab("文件加密和解密", null, panelFileEncrypt_Decrypt, null);
		panelFileEncrypt_Decrypt.setLayout(null);
		
		JButton btnOpenFile_ED = new JButton("\u9009\u62E9\u6587\u4EF6");
		btnOpenFile_ED.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser();
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					 
					String fileName = fileChooser.getSelectedFile().getPath();
					 
					textField_Name.setText(fileName);
				}
			}
		});
		btnOpenFile_ED.setBounds(115, 147, 97, 23);
		panelFileEncrypt_Decrypt.add(btnOpenFile_ED);
		
		textField_Name = new JTextField();
		textField_Name.setBounds(279, 148, 344, 21);
		panelFileEncrypt_Decrypt.add(textField_Name);
		textField_Name.setColumns(10);
		
		JPanel panel = new JPanel();
		panel.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "\u9009\u62E9\u52A0\u5BC6\u5F3A\u5EA6", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel.setBounds(109, 255, 488, 46);
		panelFileEncrypt_Decrypt.add(panel);
		panel.setLayout(null);
		
		JRadioButton rdbtnZUC_128 = new JRadioButton("ZUC-128");
		buttonGroup.add(rdbtnZUC_128);
		rdbtnZUC_128.setBounds(6, 17, 127, 23);
		panel.add(rdbtnZUC_128);
		
		JRadioButton rdbtnZUC_256 = new JRadioButton("ZUC-256");
		buttonGroup.add(rdbtnZUC_256);
		rdbtnZUC_256.setBounds(180, 17, 127, 23);
		panel.add(rdbtnZUC_256);
		
		JRadioButton rdbtnSM4 = new JRadioButton("SM4");
		buttonGroup.add(rdbtnSM4);
		rdbtnSM4.setBounds(355, 17, 127, 23);
		panel.add(rdbtnSM4);
		
		JLabel lblPassword = new JLabel("\u53E3\u4EE4\uFF1A");
		lblPassword.setBounds(127, 346, 58, 15);
		panelFileEncrypt_Decrypt.add(lblPassword);
		
		JButton btnEncryptFile = new JButton("\u52A0\u5BC6\u6587\u4EF6");
		btnEncryptFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e)  {
				 
				String plainFileName = textField_Name.getText();
				String cipherFileName = plainFileName + ".enc";
				String algorithm = null;    
				int algType = 0;  
				int ivSize = 16;
				char[] password = passwordField.getPassword();				
				int keySize = 128;
				if (rdbtnZUC_128.isSelected()) {
					algType = 0;
					keySize = 128;
					ivSize = 16;
					algorithm = "ZUC-128";
				} else if (rdbtnZUC_256.isSelected()) {
					algType = 1;
					keySize = 256;
					ivSize = 25;
					algorithm = "ZUC-256";
				} else if (rdbtnSM4.isSelected()) {
					algType = 2;
					keySize = 128;
					ivSize = 16;
					algorithm = "SM4";
				}
				 
				SecretKeySpec key = passwordToKey(new String(password), keySize);
				 
				byte[] ivValue = new byte[ivSize];
				SecureRandom random = new SecureRandom();
				random.nextBytes(ivValue);
				IvParameterSpec iv = new IvParameterSpec(ivValue);
					 
					Cipher cipher = null;
					try {
						cipher = Cipher.getInstance(algorithm, "BC");
					} catch (NoSuchAlgorithmException e2) {
						 
						e2.printStackTrace();
					} catch (NoSuchProviderException e2) {
						 
						e2.printStackTrace();
					} catch (NoSuchPaddingException e2) {
						 
						e2.printStackTrace();
					}
					try {
						cipher.init(Cipher.ENCRYPT_MODE, key, iv);
					} catch (InvalidKeyException e2) {
						 
						e2.printStackTrace();
					} catch (InvalidAlgorithmParameterException e2) {
						 
						e2.printStackTrace();
					}
					 
					try (FileOutputStream fos = new FileOutputStream(cipherFileName)) {
						 
						fos.write(algType);
						 
						fos.write(keySize / 8);
						 
						fos.write(ivSize);
						 
						fos.write(ivValue);
						try (FileInputStream fis = new FileInputStream(plainFileName);
								CipherInputStream cis = new CipherInputStream(fis, cipher)) {
							byte[] buffer = new byte[1024];
							int n = -1;
							while((n = cis.read(buffer)) != -1) {
								fos.write(buffer, 0, n);
							}
							JOptionPane.showMessageDialog(null, "文件加密成功");
						}
					} catch (FileNotFoundException e1) {
						 
						e1.printStackTrace();
					} catch (IOException e1) {
						 
						e1.printStackTrace();
					}
			}
		});
		btnEncryptFile.setBounds(115, 455, 127, 67);
		panelFileEncrypt_Decrypt.add(btnEncryptFile);
		
		JButton btnDecryptFile = new JButton("\u89E3\u5BC6\u6587\u4EF6");
		btnDecryptFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				 
				String cipherFileName = textField_Name.getText();  
				String decryptedFileName = cipherFileName + ".dec";
				int algType = 0;  
				int keySize = 0;  
				int ivSize = 0;   
				String algorithm = "";
				char[] password = passwordField.getPassword();  

				try(FileInputStream fis = new FileInputStream(cipherFileName)) {
					 
					algType = fis.read();
					 
					keySize = fis.read() * 8; 
					 
					ivSize = fis.read(); 
					 
					byte[] ivValue = new byte[ivSize]; 
					fis.read(ivValue);
					 
					IvParameterSpec iv = new IvParameterSpec(ivValue);
					SecretKeySpec key = passwordToKey(new String(password), keySize);
					if (algType == 0 ) {
						algorithm = "ZUC-128";
					}else if (algType == 1) {
						algorithm = "ZUC-256";
					}else {
						algorithm = "SM4";
					}
					
					Cipher cipher = Cipher.getInstance(algorithm, "BC");
					cipher.init(Cipher.DECRYPT_MODE, key, iv);
					try (CipherInputStream cis = new CipherInputStream(fis, cipher);
							FileOutputStream fos = new FileOutputStream(decryptedFileName)) {
						byte[] buffer = new byte[1024];
						int n = -1;
						while((n = cis.read(buffer)) != -1) {
							fos.write(buffer, 0, n);
						}
 
 
 
						JOptionPane.showMessageDialog(null, "文件解密成功");
					} catch (IOException e1) {
						 
						e1.printStackTrace();
					}
				} catch (NoSuchAlgorithmException e1) {
					 
					e1.printStackTrace();
				} catch (NoSuchProviderException e1) {
					 
					e1.printStackTrace();
				} catch (NoSuchPaddingException e1) {
					 
					e1.printStackTrace();
				} catch (InvalidKeyException e1) {
					 
					e1.printStackTrace();
				} catch (InvalidAlgorithmParameterException e1) {
					 
					e1.printStackTrace();
				} catch (FileNotFoundException e2) {
					 
					e2.printStackTrace();
				} catch (IOException e2) {
					 
					e2.printStackTrace();
				}
			}
		});
		btnDecryptFile.setBounds(312, 455, 127, 67);
		panelFileEncrypt_Decrypt.add(btnDecryptFile);
		
		JButton btnClose2 = new JButton("\u9000\u51FA");
		btnClose2.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				System.exit(0);
			}
		});
		btnClose2.setBounds(685, 531, 97, 23);
		panelFileEncrypt_Decrypt.add(btnClose2);
		
		passwordField = new JPasswordField();
		passwordField.setBounds(279, 343, 344, 21);
		panelFileEncrypt_Decrypt.add(passwordField);
		
		JPanel panelSignature = new JPanel();
		tabbedPane.addTab("数字签名和签名认证", null, panelSignature, null);
		panelSignature.setLayout(null);
		
		JButton btnOpenSignature = new JButton("\u9009\u62E9\u9700\u8981\u7B7E\u540D\u7684\u6587\u4EF6");
		btnOpenSignature.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser();
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					 
					String fileName = fileChooser.getSelectedFile().getPath();
					 
					textFieldFile_Name2.setText(fileName);
				}
			}
		});
		btnOpenSignature.setBounds(124, 36, 163, 46);
		panelSignature.add(btnOpenSignature);
		
		textFieldFile_Name2 = new JTextField();
		textFieldFile_Name2.setBounds(358, 49, 314, 21);
		panelSignature.add(textFieldFile_Name2);
		textFieldFile_Name2.setColumns(10);
		
		JButton btnSignatureFile = new JButton("\u8FDB\u884C\u7B7E\u540D");
		btnSignatureFile.addActionListener(new ActionListener()  {
			public void actionPerformed(ActionEvent e)  {
				Security.addProvider(new BouncyCastleProvider());
				String toSignFileName = textFieldFile_Name2.getText();
				String signFileName = toSignFileName + ".sign";
				
				ECPrivateKey priKey = null;
				
				KeyStore keyStore = null;
				try {
					keyStore = KeyStore.getInstance("PKCS12");
				} catch (KeyStoreException e1) {
					 
					e1.printStackTrace();
				}
				try (FileInputStream fis = new FileInputStream("F:\\java-2019-03\\javaprject\\Less4\\work")) {
					 
					Security.addProvider(new BouncyCastleProvider());
					char[] password = "123456".toCharArray();
					try {
						keyStore.load(fis, password);
					} catch (NoSuchAlgorithmException e1) {
						 
						e1.printStackTrace();
					} catch (CertificateException e1) {
						 
						e1.printStackTrace();
					}
					 
					Enumeration<String> aliases = null;
					try {
						aliases = keyStore.aliases();
					} catch (KeyStoreException e1) {
						 
						e1.printStackTrace();
					}
					 
					Collections.list(aliases).forEach(System.out::println);

					 
					KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(
							password);
					KeyStore.PrivateKeyEntry keyEntry = null;
					try {
						keyEntry = (PrivateKeyEntry) keyStore
								.getEntry("myeckey", protParam);
					} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e1) {
						 
						e1.printStackTrace();
					}
					ECPrivateKey privateKey = (ECPrivateKey) keyEntry.getPrivateKey();
					priKey = privateKey;
					 

					 
					X509Certificate certificate = null;
					try {
						certificate = (X509Certificate) keyStore.getCertificate("myeckey");
					} catch (KeyStoreException e1) {
						 
						e1.printStackTrace();
					}
					 
					ECPublicKey publicKey = (ECPublicKey) certificate.getPublicKey();
					 
				} catch (FileNotFoundException e1) {
					 
					e1.printStackTrace();
				} catch (IOException e1) {
					 
					e1.printStackTrace();
				}
			
					try {
						signFile(toSignFileName, priKey, signFileName);
						JOptionPane.showMessageDialog(null, "签名成功");
					} catch (Exception e1) {
						 
						e1.printStackTrace();
					}
			}
			
		});
		btnSignatureFile.setBounds(546, 108, 112, 46);
		panelSignature.add(btnSignatureFile);
		
		JButton btnOpenVerified = new JButton("\u9009\u62E9\u9700\u8981\u7B7E\u540D\u9A8C\u8BC1\u7684\u6587\u4EF6");
		btnOpenVerified.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser();
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					 
					String fileName = fileChooser.getSelectedFile().getPath();
					 
					textFieldVerified.setText(fileName);
				}
			}
		});
		btnOpenVerified.setBounds(136, 196, 193, 34);
		panelSignature.add(btnOpenVerified);
		
		textFieldVerified = new JTextField();
		textFieldVerified.setBounds(358, 203, 314, 21);
		panelSignature.add(textFieldVerified);
		textFieldVerified.setColumns(10);
		
		JButton btnVerify = new JButton("\u8FDB\u884C\u7B7E\u540D\u9A8C\u8BC1");
		btnVerify.addActionListener(new ActionListener() {
			private char[] a;

			public void actionPerformed(ActionEvent e) {
				Security.addProvider(new BouncyCastleProvider());
				String tobeSignFileName = textFieldVerified.getText();
				String signFilrNameString = textFieldSignValue.getText();
				 
				
				ECPublicKey pubKey = null;
				
				KeyStore keyStore = null;
				try {
					keyStore = KeyStore.getInstance("PKCS12");
				} catch (KeyStoreException e1) {
					 
					e1.printStackTrace();
				}
				try (FileInputStream fis = new FileInputStream("F:\\java-2019-03\\javaprject\\Less4\\work")) {
					 
					Security.addProvider(new BouncyCastleProvider());
					char[] password = "123456".toCharArray();
					try {
						keyStore.load(fis, password);
					} catch (NoSuchAlgorithmException e1) {
						 
						e1.printStackTrace();
					} catch (CertificateException e1) {
						 
						e1.printStackTrace();
					}
					 
					Enumeration<String> aliases = null;
					try {
						aliases = keyStore.aliases();
					} catch (KeyStoreException e1) {
						 
						e1.printStackTrace();
					}
					 
					Collections.list(aliases).forEach(System.out::println);

					 
					KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(
							password);
					KeyStore.PrivateKeyEntry keyEntry = null;
					try {
						keyEntry = (PrivateKeyEntry) keyStore
								.getEntry("myeckey", protParam);
					} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e1) {
						 
						e1.printStackTrace();
					}
					ECPrivateKey privateKey = (ECPrivateKey) keyEntry.getPrivateKey();
					 
					 

					 
					X509Certificate certificate = null;
					try {
						certificate = (X509Certificate) keyStore.getCertificate("myeckey");
					} catch (KeyStoreException e1) {
						 
						e1.printStackTrace();
					}
					 
					ECPublicKey publicKey = (ECPublicKey) certificate.getPublicKey();
					 
					pubKey = publicKey;
				} catch (FileNotFoundException e1) {
					 
					e1.printStackTrace();
				} catch (IOException e1) {
					 
					e1.printStackTrace();
				}
				
				try {
					boolean resultt = verifyFile(tobeSignFileName, pubKey, signFilrNameString);
					System.out.println(resultt);
					if ( resultt == true ) {
						textFieldResult.setText("验证成功");
					}
					else textFieldResult.setText("验证失败");
					
				} catch (Exception e1) {
					 
					e1.printStackTrace();
				}
				
			}
		});
		btnVerify.setBounds(706, 275, 112, 46);
		panelSignature.add(btnVerify);
		
		textFieldResult = new JTextField();
		textFieldResult.setBounds(297, 335, 314, 21);
		panelSignature.add(textFieldResult);
		textFieldResult.setColumns(10);
		
		JLabel lblResult = new JLabel("\u7B7E\u540D\u9A8C\u8BC1\u7684\u7ED3\u679C");
		lblResult.setBounds(175, 336, 112, 18);
		panelSignature.add(lblResult);
		
		JButton btnSignValue = new JButton("\u7B7E\u540D\u503C\u6587\u4EF6");
		btnSignValue.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser();
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					 
					String fileName = fileChooser.getSelectedFile().getPath();
					 
					textFieldSignValue.setText(fileName);
				}
			}
		});
		btnSignValue.setBounds(136, 253, 97, 23);
		panelSignature.add(btnSignValue);
		
		textFieldSignValue = new JTextField();
		textFieldSignValue.setBounds(256, 254, 306, 21);
		panelSignature.add(textFieldSignValue);
		textFieldSignValue.setColumns(10);
		
		JPanel panelMACCalulator = new JPanel();
		tabbedPane.addTab("MAC码计算", null, panelMACCalulator, null);
		panelMACCalulator.setLayout(null);
		
		JLabel lblOpenString = new JLabel("\u8F93\u5165\u5B57\u7B26\u4E32\uFF1A");
		lblOpenString.setBounds(75, 58, 95, 30);
		panelMACCalulator.add(lblOpenString);
		
		textFieldOpenString = new JTextField();
		textFieldOpenString.setBounds(166, 63, 386, 21);
		panelMACCalulator.add(textFieldOpenString);
		textFieldOpenString.setColumns(10);
		
		
		
		JCheckBox chckbxZUC_128 = new JCheckBox("ZUC-128");
		chckbxZUC_128.setBounds(75, 171, 109, 23);
		panelMACCalulator.add(chckbxZUC_128);
		
		JCheckBox chckbxZUC_256 = new JCheckBox("ZUC-256");
		chckbxZUC_256.setBounds(75, 221, 109, 23);
		panelMACCalulator.add(chckbxZUC_256);
		
		JCheckBox chckbxZUC_256_32 = new JCheckBox("ZUC-256-32");
		chckbxZUC_256_32.setBounds(75, 270, 109, 23);
		panelMACCalulator.add(chckbxZUC_256_32);
		
		JCheckBox chckbxZUC_256_64 = new JCheckBox("ZUC-256-64");
		chckbxZUC_256_64.setBounds(75, 318, 109, 23);
		panelMACCalulator.add(chckbxZUC_256_64);
		
		textFieldZUC_128 = new JTextField();
		textFieldZUC_128.setBounds(217, 172, 335, 21);
		panelMACCalulator.add(textFieldZUC_128);
		textFieldZUC_128.setColumns(10);
		
		textFieldZUC_256 = new JTextField();
		textFieldZUC_256.setBounds(217, 222, 335, 21);
		panelMACCalulator.add(textFieldZUC_256);
		textFieldZUC_256.setColumns(10);
		
		textFieldZUC_256_32 = new JTextField();
		textFieldZUC_256_32.setBounds(217, 271, 335, 21);
		panelMACCalulator.add(textFieldZUC_256_32);
		textFieldZUC_256_32.setColumns(10);
		
		textFieldZUC_256_64 = new JTextField();
		textFieldZUC_256_64.setBounds(217, 319, 335, 21);
		panelMACCalulator.add(textFieldZUC_256_64);
		textFieldZUC_256_64.setColumns(10);
		
		JButton btnCalculateMAC = new JButton("\u8BA1\u7B97\u5B57\u7B26\u4E32MAC\u7801");
		btnCalculateMAC.addActionListener(new ActionListener() {
			
				public void actionPerformed(ActionEvent e) {
					JCheckBox[] checkboxes2 = { chckbxZUC_128, chckbxZUC_256, chckbxZUC_256_32, chckbxZUC_256_64};
					JTextField[] textFields2 = { textFieldZUC_128, textFieldZUC_256, textFieldZUC_256_32, textFieldZUC_256_64};
					String[] hashAlgs = { "ZUC-128", "ZUC-256", "ZUC-256-32", "ZUC-256-64"};
					
					String s = textFieldString.getText();
					for (int i = 0; i < checkboxes2.length; i++) {
						if (checkboxes2[i].isSelected()) {
							try {
								Security.addProvider(new BouncyCastleProvider());
								 
 
 
 
								String hashType = null;
								
								if ( i == 0) {
									hashType = "ZUC-128";
								}
								else {
									hashType = "ZUC-256";
								}
								 
								KeyGenerator generator = KeyGenerator.getInstance(hashType);
								 
								SecretKey secretKey = generator.generateKey();
								 
								byte[] key = secretKey.getEncoded();
								
								
								 
								int flag = 0;
								if ( i== 0) {
									 flag =  16;
								}
								else {
									flag = 25;
								}
								byte[] ivValue = new byte[flag];
								SecureRandom random = new SecureRandom();
								random.nextBytes(ivValue);
								IvParameterSpec iv = new IvParameterSpec(ivValue);
								
								
								
								SecretKey secretKey2 = new SecretKeySpec(key, hashType);
								
								 
								Mac mac = Mac.getInstance(hashAlgs[i]);
								
								 
									try {
										mac.init( secretKey2, iv);
									} catch (InvalidKeyException e1) {
										 
										e1.printStackTrace();
									} catch (InvalidAlgorithmParameterException e1) {
										 
										e1.printStackTrace();
									}
								
								 
 
 
 
 
 
								textFields2[i].setText(Hex.toHexString(mac.doFinal(s.getBytes())));
							} catch (NoSuchAlgorithmException e1) {
								 
								e1.printStackTrace();
							
						}
					}
				}
					
			}
		});
		btnCalculateMAC.setBounds(620, 49, 170, 48);
		panelMACCalulator.add(btnCalculateMAC);
		
		JButton btnFileMAC = new JButton("\u9009\u62E9\u6587\u4EF6\u8BA1\u7B97MAC");
		btnFileMAC.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser();
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					 
					String fileName = fileChooser.getSelectedFile().getPath();
					 
					textFieldFileName_3.setText(fileName);
				}
			}
		});
		btnFileMAC.setBounds(30, 118, 142, 36);
		panelMACCalulator.add(btnFileMAC);
		
		textFieldFileName_3 = new JTextField();
		textFieldFileName_3.setBounds(202, 126, 350, 21);
		panelMACCalulator.add(textFieldFileName_3);
		textFieldFileName_3.setColumns(10);
		
		JButton btnCalculateFileMAC = new JButton("\u8BA1\u7B97\u6587\u4EF6MAC\u503C");
		btnCalculateFileMAC.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			Security.addProvider(new BouncyCastleProvider());
			
			JCheckBox[] checkBoxs_Mac = {chckbxZUC_128, chckbxZUC_256, chckbxZUC_256_32, chckbxZUC_256_64};
			String[] macAlgs = {"ZUC-128", "ZUC-256", "ZUC-256-32", "ZUC-256-64"};
			String[] macAlgsType = {"ZUC-128", "ZUC-256", "ZUC-256", "ZUC-256"};
			int[] ivSize = {16, 25, 25, 25};

			
 
				JTextField[] textFields3 = { textFieldZUC_128, textFieldZUC_256, textFieldZUC_256_32, textFieldZUC_256_64};
 
				for (JTextField textField : textFields3) {
					textField.setText("");
				}
				 
				
					 
					String fileName = textFieldFileName_3.getText();
					fileName = fileName.replace('\\', '/');
					System.out.println(fileName);
					for (int i=0 ; i < checkBoxs_Mac.length; i++) {
					try (FileInputStream fis = new FileInputStream(fileName)){
						
							if (checkBoxs_Mac[i].isSelected()) {
								KeyGenerator keyGenerator = KeyGenerator.getInstance(macAlgsType[i], "BC");
								SecretKey secretKey = keyGenerator.generateKey();
								 
								byte[] ivValue = new byte[ivSize[i]];
								SecureRandom random = new SecureRandom();
								random.nextBytes(ivValue);
								IvParameterSpec iv = new IvParameterSpec(ivValue);
								
								Mac mac = Mac.getInstance(macAlgs[i], "BC");
								mac.init(secretKey, iv);
									 
									byte[] buffer = new byte[1024];
									int n = 0;
									while(fis.read(buffer) != -1) {
										mac.update(buffer, 0 ,n);
								}
							textFields3[i].setText(Hex.toHexString(mac.doFinal()));						
							}
						}
					catch (FileNotFoundException e1) {
						e1.printStackTrace();
					} catch (IOException e1) {
						e1.printStackTrace();
					} catch (NoSuchAlgorithmException e1) {
						 
						e1.printStackTrace();
					} catch (NoSuchProviderException e1) {
						 
						e1.printStackTrace();
					} catch (InvalidKeyException e1) {
						 
						e1.printStackTrace();
					} catch (InvalidAlgorithmParameterException e1) {
						 
						e1.printStackTrace();
					}
					}	
			}
		});
		btnCalculateFileMAC.setBounds(619, 125, 171, 23);
		panelMACCalulator.add(btnCalculateFileMAC);
	}


 
		private static SecretKeySpec passwordToKey(String password, int keySize) {
			Security.addProvider(new BouncyCastleProvider());    
			MessageDigest md = null;
			try {
				md = MessageDigest.getInstance("SHA3-256");
			} catch (NoSuchAlgorithmException e) {
				 
				e.printStackTrace();
			}
			byte[] hashValue = md.digest(password.getBytes());
			SecretKeySpec key = new SecretKeySpec(hashValue, 0, keySize / 8, "AES");
			return key;
		}
		
		public static boolean verifyFile(String fileToVerify, PublicKey key, String signValueFile) throws Exception {
			 
			Security.addProvider(new BouncyCastleProvider());
			try (FileInputStream fisFileToVerify = new FileInputStream(fileToVerify);
					FileInputStream fisSignValueFile = new FileInputStream(signValueFile)) {
				 
				Signature signature = Signature.getInstance("SHA256withSM2");
				 
				signature.initVerify(key);
				 
				byte[] buffer = new byte[1024];
				int n = 0;
				while ((n = fisFileToVerify.read(buffer)) != -1) {
					signature.update(buffer, 0, n);
				}
				 
				byte[] signatureValue = new byte[fisSignValueFile.available()];
				fisSignValueFile.read(signatureValue);
				 
				return signature.verify(signatureValue);
			}
		}

		public static void signFile(String fileToSign, PrivateKey key, String signValueFile) throws Exception {
			 
			try (FileInputStream fis = new FileInputStream(fileToSign);
					FileOutputStream fos = new FileOutputStream(signValueFile)) {
				 
				Signature signature = Signature.getInstance("SHA256withSM2");
				 
				signature.initSign(key);
				 
				byte[] buffer = new byte[1024];
				int n = 0;
				while ((n = fis.read(buffer)) != -1) {
					signature.update(buffer, 0, n);
				}
				 
				byte[] signaturValue = signature.sign();
				 
				fos.write(signaturValue);
			}
		}
}