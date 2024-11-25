# Informe del Proyecto: Firmador y Verificador de Firmas

## Participantes:

* Juan Camilo Salazar
* Sebastián Libreros

## 1. Cómo se hizo el programa

El programa fue desarrollado en Java utilizando la librería JavaFX para la interfaz gráfica y bibliotecas estándar de Java para el manejo de claves y firmas digitales. Se construyó una interfaz simple con botones que permiten al usuario realizar las funcionalidades principales: seleccionar un directorio, generar un par de claves RSA, firmar un archivo y verificar una firma. Los botones de la interfaz se habilitan dinámicamente después de que el usuario selecciona un directorio, asegurando una interacción intuitiva y clara. Además, se implementaron alertas para notificar al usuario sobre errores o resultados exitosos en cada operación.

La funcionalidad de generación de claves utiliza el algoritmo RSA con una longitud de 2048 bits. La clave pública se guarda directamente en un archivo, mientras que la clave privada es cifrada utilizando AES, con una contraseña proporcionada por el usuario. Para firmar un archivo, el programa permite seleccionar el archivo y lo firma con la clave privada. La firma generada se almacena en un archivo separado. Por otro lado, la funcionalidad de verificación permite al usuario cargar tanto el archivo original como su firma, utilizando la clave pública para validar la autenticidad de la firma. Se priorizó la seguridad al emplear algoritmos como PBKDF2 para la derivación de claves y AES para el cifrado.

## 2. Dificultades enfrentadas

Durante el desarrollo se enfrentaron varios desafíos. Uno de los principales fue la configuración de JavaFX en el entorno de desarrollo, lo que requirió ajustes específicos en las dependencias y configuraciones del proyecto. En cuanto a la encriptación, la implementación de un vector de inicialización fijo planteó dudas sobre su impacto en la seguridad, lo que llevó a considerar mejoras para futuros desarrollos. Asimismo, el manejo de errores relacionados con contraseñas incorrectas o fallos en la lectura de archivos fue complejo, especialmente al mostrar estos errores de forma clara en la interfaz gráfica. También hubo problemas al manejar permisos de lectura y escritura en sistemas con restricciones, lo que demandó pruebas adicionales en diferentes entornos operativos.

## 3. Conclusiones

El desarrollo de este programa permitió afianzar conocimientos sobre criptografía asimétrica y su aplicación en proyectos prácticos. Aunque cumple con los requisitos establecidos, se identificaron áreas de mejora, como la implementación de mejores prácticas de seguridad y la posibilidad de soportar algoritmos más modernos como ECC. Este proyecto constituye una base sólida para expandir las funcionalidades en el futuro y desarrollar herramientas criptográficas más avanzadas y seguras.
