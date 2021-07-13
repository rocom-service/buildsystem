[cmdletbinding()]
param(
    [Parameter(Mandatory=$true,
               Position=0,
               ParameterSetName="BuildParameterSetName",
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               HelpMessage="Builds the container with docker build.")]
    [Switch]
    $Build,

    [Parameter(Mandatory=$true,
               Position=0,
               ParameterSetName="RunParameterSetName",
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               HelpMessage="Starts container with docker run.")]
    [Switch]
    $Run
)

function Build {
    docker build `
        --build-arg VERSION=$((cmd /c ver | Out-String) -replace '[^\d\.]','') `
        --rm `
        --isolation process `
        -t "vb6" `
        .
}
function Run {
    docker run `
        -it `
        --isolation process `
        --rm `
        vb6
}


if ($Build) {
    Build
} elseif($Run) {
    Run
}