import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.HeadlessException;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JTabbedPane;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JTextArea;
import javax.swing.border.TitledBorder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.swing.border.EtchedBorder;
import java.awt.Color;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.ImageIcon;
import javax.swing.JRadioButton;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ButtonGroup;
import javax.swing.JPasswordField;
import javax.swing.JCheckBox;
import java.awt.event.ActionListener;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.awt.event.ActionEvent;

public class GMTool extends JFrame {

	private JPanel contentPane;
	private JTextField textFieldHashInput;
	private JTextField textFieldEncryptInput;
	private final ButtonGroup buttonGroup = new ButtonGroup();
	private JPasswordField passwordFieldEncryptPassword;
	private JTextField textFieldSigInputFile;
	private JTextField textField_MacInput;
	private JTextField textField_Mac_ZUC_128_Output;
	private JTextField textField_Mac_ZUC_256_Output;
	private JTextField textField_Mac_ZUC_256_32_Output;
	private JTextField textField_Mac_ZUC_256_64_Output;
	private JTextField textField_1;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					GMTool frame = new GMTool();
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
	public GMTool() {
		setTitle("\u56FD\u5BC6\u7B97\u6CD5\u5DE5\u5177\u5305");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 737, 344);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));
		setContentPane(contentPane);
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		contentPane.add(tabbedPane, BorderLayout.CENTER);
		
		JPanel panel_Hash = new JPanel();
		tabbedPane.addTab("\u54C8\u5E0C\u8BA1\u7B97", null, panel_Hash, null);
		panel_Hash.setLayout(null);
		
		JPanel panel = new JPanel();
		panel.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "\u9009\u62E9\u52A0\u5BC6\u7C7B\u578B", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel.setBounds(16, 21, 506, 237);
		panel_Hash.add(panel);
		panel.setLayout(null);
		
		JComboBox comboBox_HashType = new JComboBox();
		comboBox_HashType.setBounds(27, 27, 56, 23);
		panel.add(comboBox_HashType);
		comboBox_HashType.setModel(new DefaultComboBoxModel(new String[] {"\u6587\u4EF6", "\u5B57\u7B26\u4E32"}));
		// 哈希计算界面文件输入框
		textFieldHashInput = new JTextField();
		textFieldHashInput.setBounds(93, 28, 314, 21);
		panel.add(textFieldHashInput);
		textFieldHashInput.setColumns(10);
		// 哈希计算界面浏览按钮
		JButton btnHashBrowse = new JButton("\u6D4F\u89C8");
		btnHashBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:/");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					//获取所选文件的绝对路径
					String fileName = fileChooser.getSelectedFile().getPath();
					//将获取到的路径传给textFieldHashInput
					textFieldHashInput.setText(fileName);
				}
			}
		});
		btnHashBrowse.setBounds(417, 27, 64, 23);
		panel.add(btnHashBrowse);
		
		JTextArea textAreaHashOutput = new JTextArea();
		textAreaHashOutput.setEditable(false);
		textAreaHashOutput.setBounds(27, 94, 454, 101);
		panel.add(textAreaHashOutput);
		
		JLabel lblNewLabel = new JLabel("\u54C8\u5E0C\u503C\uFF1A");
		lblNewLabel.setBounds(25, 69, 58, 15);
		panel.add(lblNewLabel);
		
		JButton btnHashCalculate = new JButton("\u8BA1\u7B97");
		btnHashCalculate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// 清空输出
				textAreaHashOutput.setText("");			
				// 判断文件类型
				if (comboBox_HashType.getSelectedIndex() == 0) {
					//计算文件哈希值
					String fileName = textFieldHashInput.getText();
					fileName = fileName.replace('\\', '/');
					try (FileInputStream fis = new FileInputStream(fileName)){						
							MessageDigest md = MessageDigest.getInstance("SM3");
							try (DigestInputStream dis = new DigestInputStream(fis, md)) {
								// 方法4：每次读一个数组（每次最多读1024个字节），速度快
								byte[] buffer = new byte[1024];
								while(dis.read(buffer) != -1);
							}
							textAreaHashOutput.setText(Hex.toHexString(md.digest()));												
					} catch (FileNotFoundException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}else {
					//计算字符串的哈希值
					String s = textFieldHashInput.getText();
					MessageDigest md = null;
					try {
						md = MessageDigest.getInstance("SM3");
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					textAreaHashOutput.setText(Hex.toHexString(md.digest(s.getBytes())));
				}
			}
		});
		btnHashCalculate.setBounds(560, 32, 97, 50);
		panel_Hash.add(btnHashCalculate);
		
		JPanel panel_Encryptor = new JPanel();
		tabbedPane.addTab("\u6587\u4EF6\u52A0\u89E3\u5BC6", null, panel_Encryptor, null);
		panel_Encryptor.setLayout(null);
		
		JPanel panel_2 = new JPanel();
		panel_2.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "\u9009\u62E9\u5F85\u5904\u7406\u6587\u4EF6", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_2.setBounds(9, 28, 474, 214);
		panel_Encryptor.add(panel_2);
		panel_2.setLayout(null);
		
		textFieldEncryptInput = new JTextField();
		textFieldEncryptInput.setBounds(42, 22, 337, 21);
		panel_2.add(textFieldEncryptInput);
		textFieldEncryptInput.setColumns(10);
		
		JLabel lblNewLabel_1 = new JLabel("New label");
		lblNewLabel_1.setBounds(12, 17, 25, 30);
		panel_2.add(lblNewLabel_1);
		lblNewLabel_1.setIcon(new ImageIcon("E:\\JavaProgram\\Lesson4\\img\\file.png"));
		
		JButton btnEncryptBrowse = new JButton("\u6D4F\u89C8");
		btnEncryptBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:/");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					//获取所选文件的绝对路径
					String fileName = fileChooser.getSelectedFile().getPath();
					//将获取到的路径传给textFieldEncryptInput
					textFieldEncryptInput.setText(fileName);
				}
			}
		});
		btnEncryptBrowse.setBounds(389, 21, 63, 23);
		panel_2.add(btnEncryptBrowse);
		
		JPanel panelAlgorithmChooser = new JPanel();
		panelAlgorithmChooser.setBounds(6, 65, 446, 46);
		panel_2.add(panelAlgorithmChooser);
		panelAlgorithmChooser.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "\u52A0\u5BC6\u7B97\u6CD5", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panelAlgorithmChooser.setLayout(null);
		
		JRadioButton rdbtnZUC_128 = new JRadioButton("ZUC-128");
		buttonGroup.add(rdbtnZUC_128);
		rdbtnZUC_128.setBounds(6, 17, 127, 23);
		panelAlgorithmChooser.add(rdbtnZUC_128);
		
		JRadioButton rdbtnZUC_256 = new JRadioButton("ZUC-256");
		buttonGroup.add(rdbtnZUC_256);
		rdbtnZUC_256.setBounds(135, 17, 127, 23);
		panelAlgorithmChooser.add(rdbtnZUC_256);
		
		JRadioButton rdbtnSM4 = new JRadioButton("SM4");
		buttonGroup.add(rdbtnSM4);
		rdbtnSM4.setBounds(264, 17, 127, 23);
		panelAlgorithmChooser.add(rdbtnSM4);
		
		JLabel lblEncryptPassword = new JLabel("\u53E3\u4EE4\uFF1A");
		lblEncryptPassword.setBounds(12, 132, 58, 15);
		panel_2.add(lblEncryptPassword);
		
		passwordFieldEncryptPassword = new JPasswordField();
		passwordFieldEncryptPassword.setBounds(12, 157, 440, 21);
		panel_2.add(passwordFieldEncryptPassword);
		
		JButton btnEncrypt = new JButton("\u52A0\u5BC6");
		btnEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//  加密文件
				String plainFileName = textFieldEncryptInput.getText();
				String cipherFileName = plainFileName + ".enc";
				String algorithm = null;   // 定义加密算法变量
				int algType = 0; // 定义加密算法类型，用来写在加密文件里，以便解密时使用ZUC-128 = 0; ZUC-256 = 1; SM4 = 2;
				int ivSize = 16;
				char[] password = passwordFieldEncryptPassword.getPassword();				
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
				// 基于口令生成密钥
				SecretKeySpec key = passwordToKey(new String(password), keySize);
				// 随机生成IV
				byte[] ivValue = new byte[ivSize];
				SecureRandom random = new SecureRandom();
				random.nextBytes(ivValue);
				IvParameterSpec iv = new IvParameterSpec(ivValue);
					// 创建cipher对象
					Cipher cipher = null;
					try {
						cipher = Cipher.getInstance(algorithm, "BC");
					} catch (NoSuchAlgorithmException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					} catch (NoSuchProviderException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					} catch (NoSuchPaddingException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					}
					try {
						cipher.init(Cipher.ENCRYPT_MODE, key, iv);
					} catch (InvalidKeyException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					} catch (InvalidAlgorithmParameterException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					}
					// 将密钥长度和iv写到密文文件开头
					try (FileOutputStream fos = new FileOutputStream(cipherFileName)) {
						// 在密文文件开头写入加密算法类型(用了一个字节)，单位是字节
						fos.write(algType);
						// 接着在密文文件里写入密钥长度(用了一个字节)，单位是字节
						fos.write(keySize / 8);
						// 接着在密文文件里写入IV的长度
						fos.write(ivSize);
						// 接着在密文文件开头写入iv(用了ivSize个字节)
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
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
			}
		});
		btnEncrypt.setBounds(553, 46, 96, 60);
		panel_Encryptor.add(btnEncrypt);
		
		JButton btnDecrypt = new JButton("\u89E3\u5BC6");
		btnDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// 解密文件
				String cipherFileName = textFieldEncryptInput.getText(); // 获取待解密的密文文件名
				String decryptedFileName = cipherFileName + ".dec";
				int algType = 0; // 定义加密算法类型，用来写在加密文件里，以便解密时使用ZUC-128 = 0; ZUC-256 = 1; SM4 = 2;
				int keySize = 0; // 定义密钥长度
				int ivSize = 0;  //定义IV长度
				String algorithm = "";
				char[] password = passwordFieldEncryptPassword.getPassword(); // 读入口令

				try(FileInputStream fis = new FileInputStream(cipherFileName)) {
					// 从密文文件开头读取算法类型
					algType = fis.read();
					// 从密文文件读取密钥长度
					keySize = fis.read() * 8; 
					// 从密文文件里读出IV长度
					ivSize = fis.read(); 
					// 从密文中读出IV值
					byte[] ivValue = new byte[ivSize]; 
					fis.read(ivValue);
					// 根据得到的IV值恢复IV
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
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchProviderException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (InvalidKeyException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (InvalidAlgorithmParameterException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (FileNotFoundException e2) {
					// TODO Auto-generated catch block
					e2.printStackTrace();
				} catch (IOException e2) {
					// TODO Auto-generated catch block
					e2.printStackTrace();
				}
			}
		});
		btnDecrypt.setBounds(553, 152, 97, 60);
		panel_Encryptor.add(btnDecrypt);
		
		JPanel panel_Signature = new JPanel();
		tabbedPane.addTab("\u7B7E\u540D\u9A8C\u8BC1", null, panel_Signature, null);
		panel_Signature.setLayout(null);
		
		JPanel panel_3 = new JPanel();
		panel_3.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "\u6587\u4EF6\u914D\u7F6E", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_3.setBounds(16, 29, 501, 162);
		panel_Signature.add(panel_3);
		panel_3.setLayout(null);
		
		textFieldSigInputFile = new JTextField();
		textFieldSigInputFile.setBounds(6, 53, 356, 21);
		panel_3.add(textFieldSigInputFile);
		textFieldSigInputFile.setColumns(10);
		
		JLabel lblNewLabel_2 = new JLabel("\u9009\u62E9\u6587\u4EF6\uFF1A");
		lblNewLabel_2.setBounds(6, 28, 68, 15);
		panel_3.add(lblNewLabel_2);
		
		JLabel lblNewLabel_3 = new JLabel("\u9009\u62E9\u7B7E\u540D\u6587\u4EF6\uFF08.sig\uFF09\uFF1A");
		lblNewLabel_3.setBounds(6, 91, 150, 15);
		panel_3.add(lblNewLabel_3);
		
		textField_1 = new JTextField();
		textField_1.setBounds(6, 116, 356, 21);
		panel_3.add(textField_1);
		textField_1.setColumns(10);
		
		JButton btnSignatureFileBrowse = new JButton("\u6D4F\u89C8");
		btnSignatureFileBrowse.setBounds(393, 52, 76, 23);
		panel_3.add(btnSignatureFileBrowse);
		
		JButton btnSignatureSIGFileBrowse = new JButton("\u6D4F\u89C8");
		btnSignatureSIGFileBrowse.setBounds(393, 115, 76, 23);
		panel_3.add(btnSignatureSIGFileBrowse);
		
		JButton btnSignature = new JButton("\u7B7E\u540D");
		btnSignature.setBounds(562, 47, 97, 47);
		panel_Signature.add(btnSignature);
		
		JButton btnVerification = new JButton("\u9A8C\u8BC1");
		btnVerification.setBounds(562, 127, 97, 47);
		panel_Signature.add(btnVerification);
		
		JPanel panel_Mac = new JPanel();
		tabbedPane.addTab("Mac\u7801\u8BA1\u7B97", null, panel_Mac, null);
		panel_Mac.setLayout(null);
		
		JPanel panel_1 = new JPanel();
		panel_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "\u9009\u62E9\u6587\u4EF6", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_1.setBounds(16, 17, 517, 222);
		panel_Mac.add(panel_1);
		panel_1.setLayout(null);
		
		JComboBox comboBox_Mac = new JComboBox();
		comboBox_Mac.setBounds(6, 17, 63, 23);
		panel_1.add(comboBox_Mac);
		comboBox_Mac.setModel(new DefaultComboBoxModel(new String[] {"\u6587\u4EF6", "\u5B57\u7B26\u4E32"}));
		
		textField_MacInput = new JTextField();
		textField_MacInput.setBounds(79, 18, 333, 21);
		panel_1.add(textField_MacInput);
		textField_MacInput.setColumns(10);
		
		JButton btnMacBrowse = new JButton("\u6D4F\u89C8");
		btnMacBrowse.setBounds(422, 17, 69, 23);
		panel_1.add(btnMacBrowse);
		
		JCheckBox chckbx_Mac_ZUC_128 = new JCheckBox("ZUC-128");
		chckbx_Mac_ZUC_128.setBounds(6, 68, 95, 23);
		panel_1.add(chckbx_Mac_ZUC_128);
		
		JCheckBox chckbxMac_ZUC_256 = new JCheckBox("ZUC-256");
		chckbxMac_ZUC_256.setBounds(6, 103, 95, 23);
		panel_1.add(chckbxMac_ZUC_256);
		
		JCheckBox chckbxMac_ZUC_256_32 = new JCheckBox("ZUC-256-32");
		chckbxMac_ZUC_256_32.setBounds(6, 134, 95, 23);
		panel_1.add(chckbxMac_ZUC_256_32);
		
		JCheckBox chckbxMac_ZUC_256_64 = new JCheckBox("ZUC-256-64");
		chckbxMac_ZUC_256_64.setBounds(6, 166, 95, 23);
		panel_1.add(chckbxMac_ZUC_256_64);
		
		textField_Mac_ZUC_128_Output = new JTextField();
		textField_Mac_ZUC_128_Output.setBounds(107, 69, 384, 21);
		panel_1.add(textField_Mac_ZUC_128_Output);
		textField_Mac_ZUC_128_Output.setEditable(false);
		textField_Mac_ZUC_128_Output.setColumns(10);
		
		textField_Mac_ZUC_256_Output = new JTextField();
		textField_Mac_ZUC_256_Output.setBounds(107, 104, 384, 21);
		panel_1.add(textField_Mac_ZUC_256_Output);
		textField_Mac_ZUC_256_Output.setEditable(false);
		textField_Mac_ZUC_256_Output.setColumns(10);
		
		textField_Mac_ZUC_256_32_Output = new JTextField();
		textField_Mac_ZUC_256_32_Output.setBounds(107, 135, 384, 21);
		panel_1.add(textField_Mac_ZUC_256_32_Output);
		textField_Mac_ZUC_256_32_Output.setEditable(false);
		textField_Mac_ZUC_256_32_Output.setColumns(10);
		
		textField_Mac_ZUC_256_64_Output = new JTextField();
		textField_Mac_ZUC_256_64_Output.setBounds(107, 167, 384, 21);
		panel_1.add(textField_Mac_ZUC_256_64_Output);
		textField_Mac_ZUC_256_64_Output.setEditable(false);
		textField_Mac_ZUC_256_64_Output.setColumns(10);
		
		JButton btnMacCacluate = new JButton("\u8BA1\u7B97");
		btnMacCacluate.setBounds(574, 103, 97, 52);
		panel_Mac.add(btnMacCacluate);
	}
	// 基于口令生成密钥
		private static SecretKeySpec passwordToKey(String password, int keySize) {
			MessageDigest md = null;
			try {
				md = MessageDigest.getInstance("SHA3-256");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			byte[] hashValue = md.digest(password.getBytes());
			SecretKeySpec key = new SecretKeySpec(hashValue, 0, keySize / 8, "AES");
			return key;
		}
}
