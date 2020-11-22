/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package desrod;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFileChooser;


/**
 *
 * @author Rod
 */
public class des extends javax.swing.JFrame {

    /**
     * Creates new form des
     */
    public des() {
        initComponents();
        this.setLocationRelativeTo(null);
        this.setTitle("Rodriguez Galindo Rodrigo - 5IV6");
        salida.setText("Registro:\n");
    }
    
    File ficheroACifrar = null;
    JFileChooser ficheros = new JFileChooser();
    boolean usarDES = true;
    
    boolean verificarFicheroYContrasena(){
        if (ficheroACifrar == null) {
            return false;
        }
        if (!ficheroACifrar.exists()) {
            return false;
        }
        
        //La verificacion de contraseña solo aplica para AES, ya que DES genera una
        String contr = cont.getText();
        if (contr.equals("") && aes.isSelected()) {
            return false;
        }
        else if (aes.isSelected()) {
            Pattern patron = Pattern.compile("[0-9a-z-.A-Z]{16,32}");
            Matcher comprobador = patron.matcher(contr);
            if (!comprobador.matches()) {
                return false;
            }
            if (contr.length() != 16 && contr.length() != 24 && contr.length() != 32) {
                return false;
            }
        }
        
        
        return true;
    }
    
    void DesCifrarAES(boolean estaDescifrando){
        if (verificarFicheroYContrasena()) {
            AES cifradoAES = new AES();
            if (estaDescifrando) {
                salida.setText(salida.getText() + cifradoAES.decodificar(ficheroACifrar, cont.getText()));
            }
            else{
                salida.setText(salida.getText() + cifradoAES.codificar(ficheroACifrar, cont.getText()));
            }
        }
        else{
            salida.setText(salida.getText() + "Asegurese de haber seleccionado un archivo\n"
                                            + "Asegurese que la contraseña es de 16, 24 o 32 caracteres para AES\n"
                                            + "Asegurese que la contraseña solo contiene estos caracteres (AES):\n"
                                            + "     Números, letras y .-\n");
        }
    }
    
    void DesCifrarDES(boolean estaDescifrando){
        if (verificarFicheroYContrasena()) {
            DES cifradoDES = new DES();
            if (estaDescifrando) {
                salida.setText(salida.getText() + cifradoDES.decodificar(ficheroACifrar, cont.getText()));
            }
            else{
                salida.setText(salida.getText() + cifradoDES.codificar(ficheroACifrar));
                cont.setText("");
            }
        }
        else{
            salida.setText(salida.getText() + "Asegurese de haber seleccionado un archivo\n"
                                            + "Asegurese que la contraseña es de 16, 24 o 32 caracteres para AES\n"
                                            + "Asegurese que la contraseña solo contiene estos caracteres (AES):\n"
                                            + "     Números, letras y .-\n");
        }
    }
    
    public class DES {
        KeyGenerator generadorDES;
        SecretKey clave;
        Cipher cifrador;

        FileOutputStream out = null;
        FileInputStream in = null;
        int bytesleidos;
        byte[] buffer = new byte[1000];
        byte[] bufferCifrado;
        byte[] bufferPlano;

        public String codificar(File fichero){
            try{
                generadorDES = KeyGenerator.getInstance("DES");
                generadorDES.init(56);
                clave = generadorDES.generateKey();
                cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
                System.out.println("la clave es: " + clave);
                mostrarBytes(clave.getEncoded());
                System.out.println("");
                System.out.println("Clave codificada " + clave.getEncoded());
                System.out.println();
                cifrador.init(Cipher.ENCRYPT_MODE, clave);
                in = new FileInputStream(fichero);
                File cifrado = new File(fichero.getParent() + "\\" + fichero.getName() + ".codifDES");
                cifrado.createNewFile();
                out = new FileOutputStream(cifrado);
                bytesleidos = in.read(buffer, 0, 1000);
                while(bytesleidos != -1){
                    bufferCifrado  = cifrador.update(buffer, 0, bytesleidos);
                    out.write(bufferCifrado);
                    bytesleidos = in.read(buffer, 0, bytesleidos);
                }
                
                bufferCifrado = cifrador.doFinal();
                out.write(bufferCifrado);
                in.close();
                out.close();

                String claveString = Base64.getEncoder().encodeToString(clave.getEncoded());
                return "El resultado esta en: " + (cifrado.getPath() + "\n") + "La contraseña es: " + claveString + "\n";
            }
            catch(Exception e){
                try {
                    in.close();
                    out.close();
                } catch (Exception ex1) {System.out.println("murio");}
                return "Error, intente de nuevo\n"
                     + "Asegurese que los archivos existen\n";
            }
        }

        public String decodificar(File fichero, String clave){
            try {
                generadorDES = KeyGenerator.getInstance("DES");
                generadorDES.init(56);
                cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
                
                byte[] claveDecodificada = Base64.getDecoder().decode(clave);
                SecretKey claveOriginal = new SecretKeySpec(claveDecodificada, 0, claveDecodificada.length, "DES");
                cifrador.init(Cipher.DECRYPT_MODE, claveOriginal);

                in = new FileInputStream(fichero);
            
                File descifrado = new File(fichero.getParent() + "\\" + fichero.getName() + ".decoDES");
                out = new FileOutputStream(descifrado);
            
                bytesleidos = in.read(buffer, 0, 1000);
                while(bytesleidos != -1){
                    bufferPlano  = cifrador.update(buffer, 0, bytesleidos);
                    out.write(bufferPlano);
                    bytesleidos = in.read(buffer, 0, bytesleidos);
                }
                  
                bufferPlano = cifrador.doFinal();
                out.write(bufferPlano);
                in.close();
                out.close();
                
                return "El resultado esta en: " + (descifrado.getPath() + "\n");
            } catch (Exception ex) {
                try {
                    in.close();
                    out.close();
                } catch (Exception ex1) {System.out.println("murio");}
                return "Error, intente de nuevo\n"
                     + "Asegurese que los archivos existen\n"
                     + "Aegurese que la contraseña es correcta\n";
            }
        }

        void mostrarBytes(byte[] buffer) {
            //que este metodo nos va a convertir los archivos en bytes
            System.out.write(buffer, 0, buffer.length);
        }
    }
    
    public class AES {
    
    SecretKeySpec key;
    Cipher cipher;
    FileOutputStream out = null;
    FileInputStream in = null;
    
    String codificar(File fichero, String llavesimetrica) {
        try {
            cipher = Cipher.getInstance("AES");
            key = new SecretKeySpec(llavesimetrica.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            File cifrado = new File(fichero.getParent() + "\\" + fichero.getName() + ".codiAES");
            in = new FileInputStream(fichero);
            cifrado.createNewFile();
            out = new FileOutputStream(cifrado);
            out.write(cipher.doFinal(in.readAllBytes()));
            in.close();
            out.close();
            
            return "El resultado esta en:" + (cifrado.getPath()) + "\n";
        } catch (Exception ex) {
            try {
                in.close();
                out.close();
            } catch (IOException ex1) {System.out.println("murio");}
            return "Error, intente de nuevo\n"
                 + "Asegurese que los archivos existen\n"
                 + "Aegurese que la contraseña es correcta\n";
        }
    }
    
    String decodificar(File fichero, String llavesimetrica){
        try {
            cipher = Cipher.getInstance("AES");
            key = new SecretKeySpec(llavesimetrica.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            File descifrado = new File(fichero.getParent() + "\\" + fichero.getName() + ".decoAES");
            in = new FileInputStream(fichero);
            descifrado.createNewFile();
            out = new FileOutputStream(descifrado);
            out.write(cipher.doFinal(in.readAllBytes()));
            in.close();
            out.close();
        
            return "El resultado esta en:" + (descifrado.getPath()) + "\n";
        } catch (Exception ex) {
            try {
                in.close();
                out.close();
            } catch (IOException ex1) {System.out.println("murio");}
            return "Error, intente de nuevo\n"
                 + "Asegurese que los archivos existen\n"
                 + "Aegurese que la contraseña es correcta\n";
        }
    }
}

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        aes = new javax.swing.JCheckBox();
        fichero = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        cont = new javax.swing.JTextField();
        cifrar = new javax.swing.JButton();
        descifrar = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        salida = new javax.swing.JTextArea();
        salir = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setMaximumSize(new java.awt.Dimension(300, 500));
        setMinimumSize(new java.awt.Dimension(300, 500));
        setResizable(false);

        jLabel1.setText("Cifrador A/DES");

        aes.setText("Usar AES");
        aes.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                aesActionPerformed(evt);
            }
        });

        fichero.setText("Seleccionar archivo");
        fichero.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ficheroActionPerformed(evt);
            }
        });

        jLabel2.setText("Contraseña");

        cifrar.setText("Cifrar");
        cifrar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cifrarActionPerformed(evt);
            }
        });

        descifrar.setText("Descifrar");
        descifrar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                descifrarActionPerformed(evt);
            }
        });

        salida.setEditable(false);
        salida.setColumns(20);
        salida.setRows(5);
        jScrollPane1.setViewportView(salida);

        salir.setText("Salir");
        salir.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                salirActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 380, Short.MAX_VALUE)
                    .addComponent(aes, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(cont)
                    .addComponent(fichero, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(cifrar, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(descifrar, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(salir, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(aes)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(cont, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(fichero)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(cifrar)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(descifrar)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 235, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(salir)
                .addContainerGap())
        );

        pack();
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void salirActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_salirActionPerformed
        System.exit(0);
    }//GEN-LAST:event_salirActionPerformed

    private void ficheroActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ficheroActionPerformed
        int ficheroCorrecto = ficheros.showOpenDialog(this);
        if (ficheroCorrecto == JFileChooser.APPROVE_OPTION) {
            ficheroACifrar = ficheros.getSelectedFile();
            fichero.setText("Fichero seleccionado: " + ficheroACifrar.getName());
        }
        else{
            fichero.setText("Seleccionar fichero");
        }
    }//GEN-LAST:event_ficheroActionPerformed

    private void aesActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_aesActionPerformed
        usarDES = !aes.isSelected();
    }//GEN-LAST:event_aesActionPerformed

    private void cifrarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cifrarActionPerformed
        if (usarDES) {
            DesCifrarDES(false);
        }
        else{
            DesCifrarAES(false);
        }
    }//GEN-LAST:event_cifrarActionPerformed

    private void descifrarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_descifrarActionPerformed
        if (usarDES) {
            DesCifrarDES(true);
        }
        else{
            DesCifrarAES(true);
        }
    }//GEN-LAST:event_descifrarActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox aes;
    private javax.swing.JButton cifrar;
    private javax.swing.JTextField cont;
    private javax.swing.JButton descifrar;
    private javax.swing.JButton fichero;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextArea salida;
    private javax.swing.JButton salir;
    // End of variables declaration//GEN-END:variables
}
