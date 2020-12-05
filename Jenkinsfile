pipeline {
    agent {
        docker { image 'firoorg/firo-builder:latest' }
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
                sh 'make dist'
                sh 'mkdir -p dist'
                sh 'tar -C dist --strip-components=1 -xzf firo-*.tar.gz'
                dir('dist') {
                    sh './configure --enable-elysium --enable-tests'
                    sh 'make -j6'
                }
            }
        }
        stage('Test') {
            steps {
                dir('dist') {
                    sh 'make check'
                }
            }
        }
        stage('RPC Tests') {
            steps {
                dir('dist') {
                    sh 'qa/pull-tester/rpc-tests.py -extended'
                }
            }
        }
    }
}
