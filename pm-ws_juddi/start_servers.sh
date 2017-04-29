mvn clean compile
seq 4 | xargs -Iz gnome-terminal -e "mvn exec:java"
