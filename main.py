from jwcrypto import jwk, jwe, jwt
import json

# Configurazione: Cambia questo flag per testare le due modalità
# True  = Crea un JWE che contiene un JWT (Nested)
# False = Crea un JWE che contiene una stringa semplice
USE_NESTED_JWT = False
PRIVATE_KEY_FILE = "priv_key.pem"
TOKEN_FILE = "jwe_token.txt"


def save_to_file(filename, content, is_binary=False):
    """Utility per salvare i dati su file."""
    mode = "wb" if is_binary else "w"
    with open(filename, mode) as f:
        f.write(content)
    print(f"💾 File salvato: {filename}")


def get_keys(needs_signing=False):
    """Genera le chiavi necessarie in base alla modalità."""
    # 1. Chiave RSA per la crittografia (JWE) - Serve sempre
    enc_key = jwk.JWK.generate(kty="RSA", size=2048)

    # 2. Chiave Octet per la firma (JWT) - Serve solo se usiamo JWT
    sign_key = jwk.JWK.generate(kty="oct", size=256) if needs_signing else None

    return enc_key, sign_key


def create_payload(message, mode_jwt, sign_key=None):
    """
    Prepara il payload e l'header appropriato.
    Ritorna: (payload_bytes, extra_headers_dict)
    """
    if mode_jwt and sign_key:
        print("   -> Modalità: NESTED JWT")
        # Creiamo il JWT interno
        claims = {"msg": message, "iss": "mittente", "active": True}
        jwt_token = jwt.JWT(header={"alg": "HS256"}, claims=claims)
        jwt_token.make_signed_token(sign_key)

        # Il payload del JWE sarà la stringa del JWT
        payload_bytes = jwt_token.serialize().encode("utf-8")

        # Header fondamentale per dire al ricevente che dentro c'è un token
        extra_headers = {"cty": "JWT"}
        return payload_bytes, extra_headers
    else:
        print("   -> Modalità: STRINGA SEMPLICE")
        # Il payload è semplicemente il messaggio in bytes
        payload_bytes = message.encode("utf-8")
        return payload_bytes, {}


def run_scalable_example():
    print(f"--- Avvio Esempio (Modalità JWT Nestato: {USE_NESTED_JWT}) ---")

    # --- 1. SETUP ---
    enc_key, sign_key = get_keys(needs_signing=USE_NESTED_JWT)
    public_enc_key = enc_key.export_public()  # Chiave pubblica del destinatario

    message = "This is a super secret message!"

    # --- ESPORTAZIONE CHIAVE PRIVATA ---
    # Esportiamo in formato PEM (PKCS#8)
    pem_data = enc_key.export_to_pem(private_key=True, password=None)
    save_to_file(PRIVATE_KEY_FILE, pem_data, is_binary=True)

    # --- 2. CRITTOGRAFIA (Mittente) ---
    print("\n[MITTENTE] Creazione JWE...")

    # Generiamo payload e header dinamicamente
    payload_data, custom_header = create_payload(message, USE_NESTED_JWT, sign_key)

    # Costruiamo l'header JWE completo
    protected_header = {"alg": "RSA-OAEP-256", "enc": "A256GCM", "typ": "JWE"}
    # Uniamo gli header standard con quelli specifici del payload (es. cty)
    protected_header.update(custom_header)

    # Creazione JWE
    jwe_obj = jwe.JWE(plaintext=payload_data, protected=json.dumps(protected_header))
    jwe_obj.add_recipient(jwk.JWK.from_json(public_enc_key))
    jwe_token = jwe_obj.serialize(compact=True)

    print(f"✅ Token generato (Header: {json.dumps(protected_header)})")
    save_to_file(TOKEN_FILE, jwe_token)

    ## --- 3. DECRITTOGRAFIA INTELLIGENTE (Ricevente) ---
    # print("\n[RICEVENTE] Ricezione e analisi...")
    #
    # try:
    #    # A. Decifriamo il JWE esterno
    #    received_jwe = jwe.JWE()
    #    received_jwe.deserialize(jwe_token)
    #    received_jwe.decrypt(enc_key)
    #
    #    # B. Ispezioniamo l'header per capire cosa abbiamo ricevuto
    #    # jwcrypto restituisce l'header come stringa JSON, dobbiamo convertirlo
    #    header_data = json.loads(received_jwe.objects['protected'])
    #    content_type = header_data.get("cty")
    #
    #    raw_payload = received_jwe.payload
    #    decoded_msg = ""

    #    if content_type == "JWT":
    #        print("ℹ️  Rilevato header 'cty': 'JWT'. Procedo con parsing del token interno.")
    #
    #        # Parsing del JWT interno
    #        # Nota: In un caso reale il ricevente deve avere la chiave per verificare la firma (sign_key)
    #        jwt_token = jwt.JWT(key=sign_key, jwt=raw_payload.decode('utf-8'))
    #        claims = json.loads(jwt_token.claims)
    #
    #        decoded_msg = claims.get("msg")
    #        print("✅ JWT Verificato ed estratto.")
    #
    #    else:
    #        print("ℹ️  Nessun content-type speciale. Tratto come stringa raw.")
    #        decoded_msg = raw_payload.decode('utf-8')

    #    print(f"\n--- Messaggio Finale Recuperato ---\n'{decoded_msg}'")
    #
    #    assert decoded_msg == message
    #    print("\n✅ VERIFICA RIUSCITA: Il messaggio corrisponde.")

    # except Exception as e:
    #    print(f"❌ Errore: {e}")


if __name__ == "__main__":
    run_scalable_example()
