pipeline {
    agent {
        docker { image 'zcoinofficial/zcoin-builder:latest' }
    }
    environment {
        CCACHE_DIR = '/tmp/.ccache'
    }
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
