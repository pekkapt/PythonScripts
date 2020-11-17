import PyPDF2

path = 'compress.pdf'
pdfs = [path]

writer = PyPDF2.PdfFileWriter()

for pdf in pdfs:
    reader = PyPDF2.PdfFileReader(pdf)
    for i in range(reader.numPages):
        page = reader.getPage(i)
        page.compressContentStreams()
        writer.addPage(page)

with open('compress_out.pdf', 'wb') as f:
    writer.write(f)
