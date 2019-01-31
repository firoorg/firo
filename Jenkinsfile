pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh './autogen.sh'
                sh './configure'
                sh 'make -j4'
            }
        }
        stage('Test') {
            steps {
                sh 'make check'
            }
        }
    }
}
