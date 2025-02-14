import pdfplumber

# Input and output file names
pdf_filename = "mandiant-apt1-report.pdf"
txt_filename = "mandiant-apt1.txt"

# Extract text from the PDF
with pdfplumber.open(pdf_filename) as pdf:
    text = "\n".join(page.extract_text() for page in pdf.pages if page.extract_text())

# Save extracted text to a file
with open(txt_filename, "w", encoding="utf-8") as txt_file:
    txt_file.write(text)

# Compute and print the number of tokens (characters including spaces)
num_tokens = len(text)
print(f"Number of tokens (characters including spaces): {num_tokens}")