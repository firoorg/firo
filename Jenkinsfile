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
                sh 'make dist'
                sh 'mkdir -p dist'
                sh 'tar -C dist --strip-components=1 -xzf zcoin-*.tar.gz'
                dir('dist') {
                    sh './configure --enable-elysium --enable-tests --enable-lcov'
                    sh 'make -j6'
                }
            }
        }
        stage('Test & Coverage') {
            steps {
                dir('dist') {
                    sh 'make cov -j6'
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
