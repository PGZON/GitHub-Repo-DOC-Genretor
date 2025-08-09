# Architecture of ravi_azureadbadf-main

This project utilizes Azure Data Factory components and PySpark for data processing.  The following diagram illustrates the basic interaction between these components:

```mermaid
graph LR
    subgraph Azure Data Factory
        A[Linked Service (ls_adlsgen2.json)] --> B(Integration Runtime (azureIR.json))
        B --> C(Factory (adfv2batch37dev.json))
    end
    C --> D[PySpark Notebooks (azure_realtime_scenarios)]
    D --> E[Data (emp.csv)]
```

The Azure Data Factory components are defined by JSON configuration files.  The PySpark notebooks in the `azure_realtime_scenarios` folder interact with data, likely stored in Azure Data Lake Storage Gen2, configured via the linked service.  The integration runtime facilitates the execution of PySpark code. The factory orchestrates the data processing pipeline.