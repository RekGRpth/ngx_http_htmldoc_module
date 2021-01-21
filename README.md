```nginx
location =/file2pdf { file2pdf "file.html"; } # transform FILE to PDF
location =/file2ps { file2ps "file.html"; } # transform FILE to PS
location =/file2pdf { file2pdf "file1.html" "file2.html"; } # transform several FILEs to PDF
location =/file2ps { file2ps "file1.html" "file2.html"; } # transform several FILEs to PS

location =/html2pdf { html2pdf "Hello, world!"; } # transform HTML to PDF
location =/html2ps { html2ps "Hello, world!"; } # transform HTML to PS
location =/html2pdf { html2pdf "Hello, world!" "Good bye, world!"; } # transform several HTMLs to PDF
location =/html2ps { html2ps "Hello, world!" "Good bye, world!"; } # transform several HTMLs to PS

location =/url2pdf { url2pdf "https://google.com"; } # transform URL to PDF
location =/url2ps { url2ps "https://google.com"; } # transform URL to PS
location =/url2pdf { url2pdf "https://google.com" "https://google.ru"; } # transform several URLs to PDF
location =/url2ps { url2ps "https://google.com" "https://google.ru"; } # transform several URLs to PS
```
