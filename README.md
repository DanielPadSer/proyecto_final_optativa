Proyecto: Explotación y Defensa de APIs Vulnerables — Damn Vulnerable RESTaurant API
Luis Mindalo, Einer correa, Daniel Padilla, Daniel Pacheco

Universidad Cooperativa de Colombia
Este proyecto tiene como objetivo analizar, identificar y corregir las vulnerabilidades que se encuentran en una API que está diseñada de manera intencionalmente insegura, basada en el laboratorio Damn Vulnerable RESTaurant. A lo largo de diferentes niveles, se busco detectar fallos comunes en servicios REST y aplicar prácticas seguras de desarrollo, siguiendo las categorías del OWASP API Security Top 10 (2023).

La idea principal es entender cómo surgen vulnerabilidades reales en APIs modernas, como la falta de control de acceso, problemas de autorización, escalamiento de privilegios o solicitudes inseguras al servidor. Además, se muestra, con ejemplos de código corregido, qué medidas se deben tomar para evitar estos problemas en entornos de producción.

Entorno de ejecución
Este proyecto fue desarrollado y ejecutado dentro de la terminal de windows 11, utilizando Docker para desplegar la API vulnerable Damn Vulnerable RESTaurant y sus servicios asociados.

Requisitos
Docker Engine
Docker Compose
Python 3
Burp Suite Community Edition
Visual Studio Code
Iniciar el entorno
Ejecutar en la terminal dentro del directorio del proyecto:

docker-compose build
docker-compose up -d
Verificar los contenedores:

docker ps
La API estará arrojada en:

http://localhost:8091
Documentación automática de FastAPI:

http://localhost:8091/docs
Herramientas utilizadas
Burp Suite: interceptación y explotación de endpoints
cURL: pruebas rápidas desde la terminal
VS Code: modificación del código fuente y aplicación de parches
Git: versionado y repositorio del proyecto
Con estas herramientas se hicieron las pruebas, explotaciones y validación en este repositorio.

Vulnerabilidades
Level 1 — Unrestricted Menu Item Deletion
El endpoint DELETE /menu/{item_id}, al no tener controles de autorización, permitía que cualquier usuario pudiera eliminar elementos del menú sin restricciones. Esto es un claro ejemplo de la vulnerabilidad clasificada como OWASP API5:2023 — Broken Function Level Authorization, que ocurre cuando no se aplican correctamente los controles de acceso en funciones específicas de la API. Esta falla compromete la integridad y disponibilidad de los datos al permitir que usuarios no autorizados realicen acciones sensibles, como borrar elementos críticos del sistema.

Press enter or click to view image in full size
