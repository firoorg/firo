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
                sh 'git clean -d -f -f -q -x'
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
