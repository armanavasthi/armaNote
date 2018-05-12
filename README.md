# armaNote

Steps to run this project:

### Database
Create armaNote schema in database table. <br>
Table creation is not required. If the path of db is proper in application.properties then tables will be automatically ca=reated while running the project. <br>

### Update application.properties file
Since application.properties file is added in gitignore, it cannot be directly accessed by cloning this project. <br>
Step 1: Create a file "application.properties" in armaNote.src.main.resourses location <br>
Step 2: Copy paste the code given in the following gist: <br>
https://gist.github.com/armanavasthi/62029ac11e7a8bb5c9a11350cfff7e45  <br>
Step 3: change db username and password for in the above file according to your local machine


### Running the project
Step 1: Run STS (or eclipse) (fresh new workspace is recommended) <br>
Step 2: File > import > Git > projects from git > clone URI <br>
Step 3: In opened window fill URI (https://github.com/armanavasthi/armaNote), your git username and password. Finish <br>
Step 4: Now the project will be shown in STS package explorer. <br>
Step 5: Right click on the project > Maven > update project (for the first time it can be "create as maven project") <br>
Step 6: Run as spring boot application <br>
Step 7: access localhost:6060 from your browser. <br>
Step 8: To register new user, Access localhost:6060/registration <br>