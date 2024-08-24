import pdfkit

path_to_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'  # Update path as needed
config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)

pdf = pdfkit.from_string('<h1>Hello, PDF!</h1>', False, configuration=config)

with open('output.pdf', 'wb') as f:
    f.write(pdf)