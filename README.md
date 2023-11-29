Sort of template of application with configured spring security via jwt. <br>
Spring boot version: 3.2.0 <br>
Spring Security version: 6.2.0


Don't forget to configure application.yml by your needs! <br>


If you want to use the same thing as me:
1. Install Docker
2. Pull PostgreSQL Docker image via ``docker pull postgres``
3. Run a PostgreSQL container with your desired database name, username and password: <br>
`` docker run --name postgres-db
-e POSTGRES_DB=YOURDBNAME -e POSTGRES_USER=YOURUSERNAME -e POSTGRES_PASSWORD=YOURPASSWORD -p 5432:5432 -d postgres
   ``
4. Configure application.yml (I commended where and what you should put)
5. Add your database as datasource in your IDE
