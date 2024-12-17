package montest;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.sql.SQLException;
import java.util.ArrayList;
public class InterfaceAffichage {
	 public static void main(String[] args) {
	        // Créer une instance de JFrame
	        JFrame frame = new JFrame("Browser Selection");
	        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	        frame.setSize(600, 400);

	        // Définir un layout pour le JFrame
	        frame.setLayout(new GridBagLayout());
	        GridBagConstraints gbc = new GridBagConstraints();
	        gbc.insets = new Insets(5, 5, 5, 5);
	        gbc.anchor = GridBagConstraints.WEST;

	        // Ajouter une case à cocher pour Firefox
	        JCheckBox firefoxCheckBox = new JCheckBox("Firefox");
	        gbc.gridx = 0;
	        gbc.gridy = 0;
	        frame.add(firefoxCheckBox, gbc);

	        // Ajouter une case à cocher pour Chrome
	        JCheckBox chromeCheckBox = new JCheckBox("Chrome");
	        gbc.gridx = 0;
	        gbc.gridy = 1;
	        frame.add(chromeCheckBox, gbc);

	        // Ajouter une étiquette pour la zone de texte
	        JLabel masterPasswordLabel = new JLabel("Provide Master Password if exist:");
	        gbc.gridx = 0;
	        gbc.gridy = 2;
	        frame.add(masterPasswordLabel, gbc);

	        // Ajouter une zone de texte
	        JTextField masterPasswordField = new JTextField(20);
	        gbc.gridx = 1;
	        gbc.gridy = 2;
	        frame.add(masterPasswordField, gbc);

	        // Ajouter une listbox scrollable
	        DefaultListModel<String> listModel = new DefaultListModel<>();
	        JList<String> listBox = new JList<>(listModel);
	        JScrollPane scrollPane = new JScrollPane(listBox);
	        scrollPane.setPreferredSize(new Dimension(500, 350));
	        gbc.gridx = 0;
	        gbc.gridy = 3;
	        gbc.gridwidth = 2;
	        frame.add(scrollPane, gbc);

	        // Ajouter un bouton "Decrypt"
	        JButton decryptButton = new JButton("Decrypt");
	        gbc.gridx = 0;
	        gbc.gridy = 4;
	        gbc.gridwidth = 2;
	        frame.add(decryptButton, gbc);

	        // Ajouter un listener pour le bouton
	        decryptButton.addActionListener(new ActionListener() {
	            @Override
	            public void actionPerformed(ActionEvent e) {
	                listModel.clear();

	                if (!firefoxCheckBox.isSelected() && !chromeCheckBox.isSelected()) {
	                    JOptionPane.showMessageDialog(frame, "Please select at least one option (Firefox or Chrome).", "Error", JOptionPane.ERROR_MESSAGE);
	                    return;
	                }
	                if (firefoxCheckBox.isSelected()) {
	                    firefoxLaunch firefox = new firefoxLaunch();
	                    if (!masterPasswordField.getText().isEmpty()) {
	                        firefox.setPRIMARY_PASSWORD(masterPasswordField.getText());
	                    }
	                    firefox.firefoxDecryptData();
	                    ArrayList<DecryptedData> firefoxData = firefox.getListeDonnee();
	                    if (firefoxData.isEmpty()) {
	                        listModel.addElement("No Firefox data found.");
	                    } else {
	                        listModel.addElement("Firefox:");
	                        listModel.addElement("URL Name   |   Username   |   Password");
	                        for (DecryptedData data : firefoxData) {
	                            listModel.addElement(data.getHostname() + " | " + data.getUsername() + " | " + data.getPassword());
	                        }
	                    }
	                }
	                if (chromeCheckBox.isSelected()) {
	                    ChromeLaunch chrome = new ChromeLaunch();
	                    try {
							chrome.encrypted_data_retreive_and_decryptChrome();
						} catch (SQLException e1) {
							e1.printStackTrace();
						}
	                    ArrayList<DecryptedData> chromeData = chrome.getListeDonnee();
	                    if (chromeData.isEmpty()) {
	                        listModel.addElement("No Chrome data found.");
	                    } else {
	                        listModel.addElement("Chrome:");
	                        listModel.addElement("URL Name   |   Username   |   Password");
	                        for (DecryptedData data : chromeData) {
	                            listModel.addElement(data.getHostname() + " | " + data.getUsername() + " | " + data.getPassword());
	                        }
	                    }
	                }
	            }
	        });

	        // Rendre la fenêtre visible
	        frame.setVisible(true);
	    }
	
	        
	
}
