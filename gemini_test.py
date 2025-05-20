import google.generativeai as genai

# Buraya kendi API anahtarını yaz
API_KEY = "AIzaSyBq30ksdCdUne-28cTI2ts2rNLF0z1g46A"
genai.configure(api_key=API_KEY)

model = genai.GenerativeModel('gemini-1.5-pro-latest')

try:
    response = model.generate_content("Merhaba! Bana 3 tane yaratıcı yemek ismi önerir misin?")
    print("YANIT:\n", response.text)
except Exception as e:
    print("HATA:", e) 