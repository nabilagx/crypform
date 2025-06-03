from flask import Flask, render_template, request
from crypto_utils import vigenere_encrypt, aes_encrypt
from crypto_utils import vigenere_decrypt, aes_decrypt
import csv
import datetime


app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    encrypted_data = None
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        
        # Kunci kriptografi
        vigenere_key = 'SECURE'
        aes_key = 'supersecurekey'

        # Encrypt name with Vigenere, others as is
        name_encrypted = vigenere_encrypt(name, vigenere_key)

        # Combine data
        payload = f"Name: {name_encrypted}\nEmail: {email}\nMessage: {message}"

        # Encrypt with AES
        final_encrypted = aes_encrypt(payload, aes_key)
        encrypted_data = final_encrypted

        # Proses enkripsi
        name_encrypted = vigenere_encrypt(name, vigenere_key)
        data = f"Name: {name_encrypted}\nEmail: {email}\nMessage: {message}"
        encrypted_data = aes_encrypt(data, aes_key)

        # Simpan ke CSV
        with open('data_terenkripsi.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            timestamp = datetime.datetime.now().isoformat()
            writer.writerow([timestamp, name_encrypted, email, encrypted_data])

    return render_template('form.html', encrypted_data=encrypted_data)




@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    decrypted_data = None
    if request.method == 'POST':
        ciphertext = request.form['ciphertext']
        aes_key = 'supersecurekey'  
        vigenere_key = 'SECURE'

        try:
            decrypted = aes_decrypt(ciphertext, aes_key)

            # Dekripsi bagian nama
            lines = decrypted.split('\n')
            name_line = lines[0]
            name_encrypted = name_line.split(': ')[1]
            name = vigenere_decrypt(name_encrypted, vigenere_key)

            lines[0] = f"Name: {name}"
            decrypted = '\n'.join(lines)

            decrypted_data = decrypted
        except Exception as e:
            decrypted_data = f"[ERROR] Gagal dekripsi: {str(e)}"

    return render_template('decrypt.html', decrypted_data=decrypted_data)


if __name__ == '__main__':
    app.run(debug=True)
