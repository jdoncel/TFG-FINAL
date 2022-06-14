import fileAnalysis
import WebAnalysis
import reader
import markMail

url=''
VTapiKey='fc06e14f7e9409d28771c645456c958477fb78eda4d89034bc1bde729827f2af'
mailApiKey='AIzaSyAc2vZQS7QedPd0zfqRbd7MvSkT3FYgJ4o'
nMails=0
contador=0
contadorSpam=0
analizarFichero=False
#Comprobar que hay correos recibidos
mailStored=reader.checkEmailStored()

#Comprobar que hay correos recibidos no leidos
mailUnRead=reader.checkEmailUnRead()
print("El numero de correos a analizar son :"+repr(len(mailUnRead)))
#Analisis direccion sender
if len(mailUnRead)>0:
    for i in mailUnRead:
        contador=contador+1
        print("-----------------------")
        print("\nAnalizando correo Nº"+repr(contador) +"\n")
        sCheck=reader.senderCheck(i)
        if sCheck != True:
            print("  El correo de: "+ sCheck + " no es considerado valido, porque contiene parametros no aceptados")
            # Marcar correo como spam
            contadorSpam=contadorSpam+1
            markMail.markSpam(sCheck)
            print("  Marcando correo como SPAM")
        else:
            print("Correo sender valido. \nBuscando direcciones URL.......")
            #Comprobar si los emails recibidos contienen una url
            mailWeb=reader.checkEmailHasWeb(i)
            if mailWeb == True:
                print("  El email no contiene URL")
            else:
                # Analisis web
                resultadoWeb = WebAnalysis.runWeb(VTapiKey, mailWeb)
                if resultadoWeb != True:
                    output = resultadoWeb.split('&&')
                    print("Pagina web no segura" + repr(output))
                    # Marcar como SPAM
                    contadorSpam = contadorSpam + 1
                    markMail.markSpamWeb(i)
                    print("Marcando correo como SPAM")
                else:
                    analizarFichero=True
                    print("Pagina segura.")
            if mailWeb==True or analizarFichero==True:
                print("Comprobando si el mail tiene archivos.....")
                if reader.checkEmailhasFile(i) !=True:
                    fileTerminacion=fileAnalysis.fileAnalysis(i)
                    if fileTerminacion == True  :
                        print("Este tipo de archivos esta permitido")
                    else:
                        contadorSpam=contadorSpam+1
                        print("Terminacion no segura y marcando como SPAM")
                        markMail.markSpamWeb(i)
                    ######Comprobar el Fichero
                else:
                    print("El email no contiene Ficheros")


print("\n\nLos resultados del Analisis son:\nCorreos detectados como peligrososo y marcados como spam:"+repr(contadorSpam))
print("Correos seguros: "+repr(contador-contadorSpam))
#Analisis Archivo

