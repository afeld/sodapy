# coding: utf-8

# # Example 02: SoSQL Queries
#
# Constructing custom queries to conserve bandwith and computational resources

# ## Setup

# In[1]:


import os

# Note: we don't need Pandas
# Filters allow you to accomplish many basic operations automatically

from sodapy import Socrata


# ## Find Some Data
#
# As in the first example, I'm using the Santa Fe political contribution dataset.
#
# `https://opendata.socrata.com/dataset/Santa-Fe-Contributors/f92i-ik66.json`

# In[2]:


socrata_domain = "opendata.socrata.com"
socrata_dataset_identifier = "f92i-ik66"

# If you choose to use a token, run the following command on the terminal (or add it to your .bashrc)
# $ export SODAPY_APPTOKEN=<token>
socrata_token = os.environ.get("SODAPY_APPTOKEN")


# In[3]:


client = Socrata(socrata_domain, socrata_token)


# ## Use Metadata to Plan Your Query
# You've probably looked through the column names and descriptions in the web UI,
# but it can be nice to have them right in your workspace as well.

# In[4]:


metadata = client.get_metadata(socrata_dataset_identifier)
[x["name"] for x in metadata["columns"]]


# In[5]:


meta_amount = [x for x in metadata["columns"] if x["name"] == "AMOUNT"][0]
meta_amount


# ## Efficiently Query for Data

# ### Restrict rows to above-average donations

# In[6]:


# Get the average from the metadata. Note that it's a string by default
meta_amount["cachedContents"]["average"]


# In[7]:


# Use the 'where' argument to filter the data before downloading it
results = client.get(socrata_dataset_identifier, where="amount >= 2433")
print("Total number of non-null results: {}".format(meta_amount["cachedContents"]["non_null"]))
print("Number of results downloaded: {}".format(len(results)))
results[:3]


# ### Restrict columns and order rows
# Often, you know which columns you want, so you can further simplify the download.
#
# It can also be valuable to have results in order, so that you can quickly grab the
# largest or smallest.

# In[8]:


results = client.get(
    socrata_dataset_identifier,
    where="amount < 2433",
    select="amount, job",
    order="amount ASC",
)
results[:3]


# ### Perform basic operations
# You can even accomplish some basic analytics operations like finding sums.
#
# If you're planning on doing further processing, note that the numeric outputs
# are strings by default.

# In[10]:


results = client.get(
    socrata_dataset_identifier,
    group="recipient",
    select="sum(amount), recipient",
    order="sum(amount) DESC",
)
results


# ### Break download into managable chunks
# Sometimes you do want all the data, but it would be too big for one download.
#
# By default, all queries have a limit of 1000 rows, but you can manually set it
# higher or lower. If you want to loop through results, just use `offset`

# In[11]:


results = client.get(socrata_dataset_identifier, limit=6, select="name, amount")
results


# In[11]:


loop_size = 3
num_loops = 2

for i in range(num_loops):
    results = client.get(
        socrata_dataset_identifier,
        select="name, amount",
        limit=loop_size,
        offset=loop_size * i,
    )
    print("\n> Loop number: {}".format(i))

    # This simply formats the output nicely
    for result in results:
        print(result)


# ### Query strings
# All of the queries above were made with method parameters,
# but you could also pass all the parameters at once in a
# SQL-like format

# In[13]:


query = """
select
    name,
    amount
where
    amount > 1000
    and amount < 2000
limit
    5
"""

results = client.get(socrata_dataset_identifier, query=query)
results


# ### Free text search
# My brother just got a dog named Slider, so we were curious about how many other New York City dogs had that name.
#
# Searches with `q` match anywhere in the row, which allows you to quickly search through data with several free text columns of interest.

# In[20]:


nyc_dogs_domain = "data.cityofnewyork.us"
nyc_dogs_dataset_identifier = "nu7n-tubp"

nyc_dogs_client = Socrata(nyc_dogs_domain, socrata_token)
results = nyc_dogs_client.get(
    nyc_dogs_dataset_identifier, q="Slider", select="animalname, breedname"
)
results


# # Going Further
#
# There's plenty more to do! Check out [Queries using SODA](https://dev.socrata.com/docs/queries/) for additional functionality
